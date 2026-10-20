%% @author Marc Worrell <marc@worrell.nl>
%% @copyright 2014-2026 Marc Worrell
%% @doc Access an url with the view permissions of another user.
%% @end

%% Copyright 2014-2026 Marc Worrell
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

-module(mod_access_url).

-moduledoc(#{
    zotonic_keywords => [
        "reference", "module", "site_administrator", "backend_developer",
        "frontend_developer", "authorization_and_access_control", "security", "url"
    ]
}).
-moduledoc("
Share protected pages, images and feeds using signed URLs with the signing user's
view permissions. Recipients do not need to log in as that user. Typical uses
include private calendar feeds, HTML certificate rendering and sharing a survey
with people who do not have an account.

## Setup and administration

Install the `zotonic_mod_access_url` application and enable `mod_access_url` for
the site. The module adds a **Share link to this page** widget to the admin edit
sidebar. An authenticated user who can view the resource can generate and copy
a link, choosing a duration or an indefinite link.

There are no module configuration keys. Signing secrets are created on demand
as `mod_access_url` identities associated with the signing user.

## Generate a signed URL

Add `z_access_url` to a dispatch URL generated in an authenticated context:

```django
{% url page id=id z_access_url absolute_url %}
```

To make the link valid for one hour:

```django
{% url page id=id z_access_url z_access_url_valid_for=3600 absolute_url %}
```

`z_access_url_valid_for` accepts an integer duration in seconds or a binary date
expression understood by `z_datetime:to_datetime/1`, such as `+day` or `+week`.
Omitting it creates a link without an expiry. The generated query contains the
absolute expiry timestamp; do not pass that timestamp back as an integer duration.

The same arguments can be passed to `z_dispatcher:url_for/3`, or set on a context
when generating resource page URLs. `m_access_url:generate_url/2,3` provides a
convenience API for absolute resource URLs. See `m_access_url` for model calls.

An integer `z_access_url` selects another signing user only when the caller can
edit that user's resource. Signing explicitly for user 1 requires the caller to
be user 1. Without a signing user, the URL is returned unsigned.

## Permissions and respondent identity

A valid link supplies an additional context for resource and property **view**
checks. It does not replace the visitor's logged-in identity or grant edit,
update or delete permissions. Invalid, expired and unknown tokens leave normal
request permissions in effect.

For surveys using the standard submission handler, an anonymous recipient's
answers remain anonymous in the `user_id` column and may be associated with a
browser session. A logged-in recipient's answers belong to that recipient, not
the signer. Survey settings and custom submission handlers still apply; a signed
link is not a general authorization to perform writes.

The module runs at priority 10 so its view grants can be evaluated before an ACL
module returns a denial. Custom ACL integrations must preserve that ordering.

## Images, browser sessions and expiry

Image URLs generated through the `image` dispatch while rendering a validated
access URL are signed using the validated signing user. They retain the parent
link's exact expiry, including the absence of an expiry. This allows renderers
without the visitor's login cookies to fetch protected images.

Resources granted view access can also be registered for the visitor's session
for four hours. These grants allow subsequent requests, such as survey pages,
to access those resources without resending the original signature. Grants are
kept in a site-specific ETS table on the current node and are lost when that
table is recreated. The four-hour grant period is independent of the signed
URL's expiry and can outlast it.

The `_html_body.tpl` contribution uses `m.access_url.reload_needed` to reload a
signed page after the Cotonic session cookie becomes available. Custom page
layouts should include the standard Zotonic body contributions for this behavior.
Image signatures themselves do not require a browser session.

## Signature compatibility and diagnostics

Verification accepts current Base64URL signatures and earlier Base64 signatures.
Links without an expiry can also use the historical Erlang-term signatures,
including the old `use_absolute_url` variant. Compatibility checks reconstruct
server-side data; they never deserialize a term supplied by the requester.

Failure logs distinguish `expired`, `invalid_expiry`, `malformed_signature`,
`signature_mismatch` and `unknown_user_token`. Successful verification logs the
signature format at debug level. These logs omit tokens, signatures and secrets.
Added application parameters, including tracking parameters, invalidate a link.

## Sharing and scope

Anyone holding a valid link can use it. Share links only with intended recipients
and avoid exposing them in public pages or logs. The signature binds the dispatch
and application arguments; language and internal access-URL arguments are handled
separately. It does not turn arbitrary links on the page into signed links.
Validated responses receive a noindex header.

The public `register_resource/2` helper records a session grant without checking
ACLs itself. Use it only after authorizing access; `is_resource_registered/2`
checks whether that session grant is still valid.
").

-author("Marc Worrell <marc@worrell.nl>").

-mod_title("Access URL").
-mod_description("Sign an URL for an user so that it can be used for accessing vcal feeds etc.").
-mod_prio(10).

-export([
    observe_url_rewrite/3,
    observe_middleware/3,
    observe_acl_is_allowed/2,
    observe_acl_is_allowed_prop/2,
    observe_tick_24h/2,

    init/1,

    register_resource/2,
    is_resource_registered/2
]).

-include_lib("kernel/include/logger.hrl").
-include_lib("zotonic_core/include/zotonic.hrl").

%% @doc A validated access token allows view access for four hours to all
%% resources on the initial signed page.
-define(ACCESS_PERIOD, 14_400).


%% @doc Rewrite image URLs to also allow access, this prevents the problem that
%% images might not be visible on pages that are accessed with an access url because
%% the image resources are not visible to the logged on user.
%%
%% If the `z_access_url` argument is set on the URL, then a token will be added to
%% URL for the current user.
observe_url_rewrite(#url_rewrite{ dispatch = image, args = Args }, Url, Context) ->
    case z_context:get(is_z_access_url, Context) of
        true ->
            case z_context:get(z_access_url_context, Context) of
                #context{} = AccessContext ->
                    % The request stays anonymous. Sign embedded images as the
                    % validated user, without extending the parent URL's expiry.
                    ValidFor = z_convert:to_binary(z_context:get(z_access_url_expires, Context)),
                    maybe_add_token(image, Args, Url, ValidFor, AccessContext);
                undefined ->
                    Url
            end;
        _False ->
            rewrite_if_access_url(image, Args, Url, Context)
    end;
observe_url_rewrite(#url_rewrite{ dispatch = Dispatch, args = Args }, Url, Context) ->
    rewrite_if_access_url(Dispatch, Args, Url, Context).

rewrite_if_access_url(Dispatch, Args, Url, Context) ->
    case find_arg(z_access_url, Args, Context) of
        true ->
            maybe_add_token(Dispatch, Args, Url, Context);
        ?ACL_ADMIN_USER_ID ->
            % Never allow signing for the admin user, unless the admin user is
            % logged in.
            case z_acl:user(Context) of
                ?ACL_ADMIN_USER_ID ->
                    maybe_add_token(Dispatch, Args, Url, Context);
                _ ->
                    Url
            end;
        UserId when is_integer(UserId) ->
            % Only allow signing of URLs for another user if we have full
            % access to that user's resource.
            case z_acl:rsc_editable(UserId, Context) of
                true ->
                    maybe_add_token(Dispatch, Args, Url, z_acl:logon(UserId, Context));
                false ->
                    Url
            end;
        _ ->
            Url
    end.

find_arg(Arg, Args, Context) ->
    case proplists:get_value(Arg, Args) of
        undefined -> z_context:get(Arg, Context);
        Access -> Access
    end.

%% @doc Check if the current request is signed with an access url, if so then
%% save a context with the signing user-id in the request context for later ACL
%% lookups on resources.
observe_middleware(#middleware{ on = welformed }, Context, _Context) ->
    case z_context:get_q(<<"z_access_url_token">>, Context) of
        undefined -> Context;
        <<>> -> Context;
        _ -> logon_if_sigok(Context)
    end;
observe_middleware(#middleware{ on = _ }, Context, _Context) ->
    Context.


%% @doc Check if access is allowed to the given resource id. Note that the z_access_url_context
%% must be set in the request context for adding new ids to the registered resources.
observe_acl_is_allowed(#acl_is_allowed{ action = view, object = Id } = AclCheck, Context) when is_integer(Id) ->
    case is_resource_registered(Id, Context) of
        true ->
            true;
        false ->
            UserId = z_acl:user(Context),
            case z_context:get(z_access_url_context, Context) of
                #context{ user_id = AccessUserId } when AccessUserId =:= ?ACL_ADMIN_USER_ID ->
                    register_resource(Id, Context),
                    true;
                #context{ user_id = AccessUserId } = AccessContext when UserId =/= AccessUserId ->
                    case z_notifier:first(AclCheck, AccessContext) of
                        true ->
                            register_resource(Id, Context),
                            true;
                        false -> undefined;
                        undefined -> undefined
                    end;
                #context{} ->
                    undefined;
                undefined ->
                    undefined
            end
    end;
observe_acl_is_allowed(#acl_is_allowed{}, _Context) ->
    undefined.


%% @doc Check if access is allowed to the given resource id properties.
observe_acl_is_allowed_prop(#acl_is_allowed_prop{ action = view, object = Id } = AclCheck, Context) when is_integer(Id) ->
    UserId = z_acl:user(Context),
    case z_context:get(z_access_url_context, Context) of
        #context{ user_id = AccessUserId } when AccessUserId =:= ?ACL_ADMIN_USER_ID ->
            true;
        #context{ user_id = AccessUserId } = AccessContext when UserId =/= AccessUserId ->
            case z_notifier:first(AclCheck, AccessContext) of
                true -> true;
                false -> undefined;
                undefined -> undefined
            end;
        undefined ->
            undefined
    end;
observe_acl_is_allowed_prop(#acl_is_allowed_prop{}, _Context) ->
    undefined.

%% @doc Periodically delete all expired keys from the ets tables.
observe_tick_24h(tick_24h, Context) ->
    Now = z_datetime:timestamp(),
    ets:foldl(
        fun({{SessionId, Id}, Expire}, Acc) ->
            if
                Expire >= Now ->
                    Acc;
                true ->
                    ets:delete(table_name(Context), {SessionId, Id}),
                    Acc
            end
        end, [], table_name(Context)).


%% @doc Initialize the ets table for access lookups. Called from the dummy module
%% gen_server process.
-spec init(Context) -> ok when
    Context :: z:context().
init(Context) ->
    ets:new(table_name(Context), [named_table, public, set, {keypos, 1}]),
    ok.

%% @doc Check if a resource id is registered for access exceptions. A registered resource
%% is accessible for a limited time without the need for a valid signature.
-spec is_resource_registered(Id, Context) -> boolean() when
    Id :: m_rsc:resource_id(),
    Context :: z:context().
is_resource_registered(Id, Context) ->
    case z_context:session_id(Context) of
        {ok, SessionId} ->
            case ets:lookup(table_name(Context), {SessionId, Id}) of
                [{_Key, Expire}] ->
                    Now = z_datetime:timestamp(),
                    if
                        Expire >= Now ->
                            true;
                        true ->
                            ets:delete(table_name(Context), {SessionId, Id}),
                            false
                    end;
                [] ->
                    false
            end;
        {error, _} ->
            false
    end.

%% @doc Register a resource id for access exceptions. This is used for allowing access to
%% resources like vcal feeds and images that are protected by the access url mechanism.
-spec register_resource(Id, Context) -> ok | {error, Reason} when
    Id :: m_rsc:resource_id(),
    Context :: z:context(),
    Reason :: term().
register_resource(Id, Context) ->
    case z_context:session_id(Context) of
        {ok, SessionId} ->
            Expire = z_datetime:timestamp() + ?ACCESS_PERIOD,
            ets:insert(table_name(Context), {{SessionId, Id}, Expire}),
            ok;
        {error, _}  = Error ->
            Error
    end.

table_name(SiteOrContext) ->
    z_utils:name_for_site(access_url_tokens, SiteOrContext).

%% @doc Add a token to the URL. This gives the opener of the URL access to the
%% resources shown on the given URL, using the permissions of the current user.
maybe_add_token(Dispatch, Args, Url, Context) ->
    ValidFor = z_convert:to_binary(valid_for(Args, Context)),
    maybe_add_token(Dispatch, Args, Url, ValidFor, Context).

maybe_add_token(Dispatch, Args, Url, ValidFor, Context) ->
    case z_acl:user(Context) of
        undefined ->
            Url;
        UserId when is_integer(UserId) ->
            {ok, Token, Secret} = user_secret(UserId, Context),
            Nonce = z_ids:id(),
            SignedData = signed_data(Dispatch, transmitted_args(Args), Token, Nonce, Secret, ValidFor),
            Sig = encode_v1(SignedData),
            ExtraArgs = <<"z_access_url_token=", Token/binary,
                          "&z_access_url_nonce=", Nonce/binary,
                          "&z_access_url_sig=", Sig/binary>>,
            ExtraArgs1 = if
                ValidFor =:= <<>> -> ExtraArgs;
                true -> <<ExtraArgs/binary, "&z_access_url_valid_for=", ValidFor/binary>>
            end,
            Url1 = remove_expiry_arg(Url),
            case binary:match(Url1, <<"?">>) of
                nomatch -> <<Url1/binary, $?, ExtraArgs1/binary>>;
                _ -> <<Url1/binary, $&, ExtraArgs1/binary>>
            end
    end.

%% The dispatcher may already have emitted the duration/date option. Replace
%% it with the signed absolute expiry instead of sending two query values.
remove_expiry_arg(Url) ->
    case binary:split(Url, <<"?">>) of
        [_] -> Url;
        [Path, Query] ->
            Separator = case binary:match(Query, <<"&amp;">>) of
                nomatch -> <<"&">>;
                _ -> <<"&amp;">>
            end,
            Query1 = binary:replace(Query, <<"&amp;">>, <<"&">>, [global]),
            Parts = [ P || P <- binary:split(Query1, <<"&">>, [global]),
                hd(binary:split(P, <<"=">>)) =/= <<"z_access_url_valid_for">> ],
            case Parts of
                [] -> Path;
                _ -> iolist_to_binary([Path, $?, lists:join(Separator, Parts)])
            end
    end.

valid_for(Args, Context) ->
    case find_arg(z_access_url_valid_for, Args, Context) of
        ValidFor when is_binary(ValidFor) ->
            DT = z_datetime:to_datetime(ValidFor),
            z_datetime:datetime_to_timestamp(DT);
        ValidFor when is_integer(ValidFor) ->
            Now = z_datetime:timestamp(),
            Now + ValidFor;
        undefined ->
            undefined
    end.

%% @doc Lookup the signing secret of the given user. If not set then add
%% an identity with a newly generated secret to the user's identities.
user_secret(UserId, Context) ->
    case m_identity:get_rsc_by_type(UserId, ?MODULE, Context) of
        [] ->
            Token = z_ids:id(20),
            Secret = z_ids:id(40),
            m_identity:insert_single(UserId, ?MODULE, Token, [{prop1, Secret}], Context),
            {ok, Token, Secret};
        [Idn|_] ->
            Token = proplists:get_value(key, Idn),
            Secret = proplists:get_value(prop1, Idn),
            {ok, Token, Secret}
    end.

token_user(<<>>, _Context) ->
    {error, enoent};
token_user(Token, Context) ->
    case m_identity:lookup_by_type_and_key(?MODULE, Token, Context) of
        undefined ->
            {error, enoent};
        Idn when is_list(Idn) ->
            UserId = proplists:get_value(rsc_id, Idn),
            Secret = proplists:get_value(prop1, Idn),
            {ok, UserId, Secret}
    end.

logon_if_sigok(Context) ->
    case z_context:get_controller_module(Context) of
        controller_http_error ->
            Context;
        _ ->
            Token = z_convert:to_binary(z_context:get_q(<<"z_access_url_token">>, Context)),
            Dispatch = z_context:get_q(<<"zotonic_dispatch">>, Context),
            case token_user(Token, Context) of
                {ok, UserId, Secret} ->
                    Nonce = z_context:get_q(<<"z_access_url_nonce">>, Context),
                    ValidFor = z_context:get_q(<<"z_access_url_valid_for">>, Context),
                    Sig = z_convert:to_binary(z_context:get_q(<<"z_access_url_sig">>, Context)),
                    case verify_signature(Sig, Dispatch, get_q_all(Context), Token, Nonce, Secret, ValidFor) of
                        {ok, Format} ->
                            case expiry_status(ValidFor) of
                                valid ->
                                    ?LOG_DEBUG(#{
                                        in => zotonic_mod_access_url,
                                        text => <<"Valid access URL signature on request">>,
                                        result => ok,
                                        signature_format => Format,
                                        user_id => UserId,
                                        dispatch => Dispatch
                                    }),
                                    Context1 = z_context:set(is_z_access_url, true, Context),
                                    UserContext = z_acl:logon(UserId, z_context:new(Context)),
                                    Context2 = z_context:set([
                                        {z_access_url_context, UserContext},
                                        {z_access_url_expires, ValidFor}
                                    ], Context1),
                                    z_context:set_noindex_header(true, Context2);
                                Reason ->
                                    ?LOG_INFO(#{
                                        in => zotonic_mod_access_url,
                                        text => <<"Access URL expiry check failed">>,
                                        result => error,
                                        reason => Reason,
                                        signature_format => Format,
                                        user_id => UserId,
                                        dispatch => Dispatch
                                    }),
                                    Context
                            end;
                        {error, Reason} ->
                            ?LOG_WARNING(#{
                                in => zotonic_mod_access_url,
                                text => <<"Access URL signature check failed">>,
                                result => error,
                                reason => Reason,
                                signature_size => byte_size(Sig),
                                user_id => UserId,
                                dispatch => Dispatch
                            }),
                            Context
                    end;
                {error, enoent} ->
                    ?LOG_INFO(#{
                        in => zotonic_mod_access_url,
                        text => <<"Unknown access URL token">>,
                        result => error,
                        reason => unknown_user_token,
                        dispatch => Dispatch
                    }),
                    Context
            end
    end.

%% SHA-256 signatures have a fixed encoded length. Reject other lengths before
%% serializing arguments. Never decode client data with binary_to_term/1.
verify_signature(Sig, Dispatch, Args, Token, Nonce, Secret, ValidFor)
    when byte_size(Sig) =:= 43; byte_size(Sig) =:= 44 ->
    Sig1 = fix_outlook_sig(Sig),
    Data = signed_data(Dispatch, Args, Token, Nonce, Secret, ValidFor),
    Hash = crypto:hash(sha256, Data),
    case {base64url:encode(Hash), base64:encode(Hash)} of
        {Sig1, _} -> {ok, base64url};
        {_, Sig1} -> {ok, base64};
        _ when ValidFor =:= undefined; ValidFor =:= <<>> ->
            verify_legacy(Sig1, Dispatch, filter_args(Args, []), Token, Nonce, Secret);
        _ ->
            % Historical signatures did not bind an expiry. Never use them to
            % validate a request carrying one, even when it is in the future.
            {error, signature_mismatch}
    end;
verify_signature(_Sig, _Dispatch, _Args, _Token, _Nonce, _Secret, _ValidFor) ->
    {error, malformed_signature}.

%% At most three additional hashes, only after current-format verification fails.
%% These are the exact structures emitted by the historical sign_args_old_* APIs.
verify_legacy(Sig, Dispatch, Args, Token, Nonce, Secret) ->
    Tail = [signed, z_convert:to_binary(Dispatch), z_convert:to_binary(Nonce),
        z_convert:to_binary(Token), z_convert:to_binary(Secret)],
    case legacy_signature([Args | Tail], 1) of
        Sig -> {ok, legacy_term_v1};
        _ ->
            case legacy_signature([Args | Tail], 2) of
                Sig -> {ok, legacy_term_v2};
                _ ->
                    OldArgs = lists:sort([{<<"use_absolute_url">>, <<"true">>} | Args]),
                    case legacy_signature([OldArgs | Tail], 1) of
                        Sig -> {ok, legacy_use_absolute_url};
                        _ -> {error, signature_mismatch}
                    end
            end
    end.

legacy_signature(Data, MinorVersion) ->
    base64:encode(crypto:hash(sha256,
        term_to_binary(Data, [{minor_version, MinorVersion}]))).

expiry_status(undefined) -> valid;
expiry_status(<<>>) -> valid;
expiry_status(ValidFor) ->
    try
        case z_convert:to_integer(ValidFor) >= z_datetime:timestamp() of
            true -> valid;
            false -> expired
        end
    catch
        _:_ -> invalid_expiry
    end.

encode_v1(Data) ->
    base64url:encode(crypto:hash(sha256, Data)).

%% Match z_dispatcher:filter_empty_args/1 when signing, not when verifying.
%% An attacker adding an empty application argument must still invalidate a URL.
transmitted_args(Args) ->
    lists:filter(
        fun
            ({_, <<>>}) -> false;
            ({_, []}) -> false;
            ({_, undefined}) -> false;
            ({absolute_url, _}) -> false;
            (absolute_url) -> false;
            ({zotonic_http_accept, _}) -> false;
            (_) -> true
        end,
        Args).

signed_data(Dispatch, Args, Token, Nonce, Secret, ValidFor) when ValidFor =:= <<>>; ValidFor =:= undefined ->
    [
        flatten_args(Args), $:,
        <<"signed:">>,
        z_convert:to_binary(Dispatch), $:,
        z_convert:to_binary(Nonce), $:,
        z_convert:to_binary(Token), $:,
        z_convert:to_binary(Secret)
    ];
signed_data(Dispatch, Args, Token, Nonce, Secret, ValidFor) ->
    [
        flatten_args(Args), $:,
        <<"signed:">>,
        z_convert:to_binary(Dispatch), $:,
        z_convert:to_binary(Nonce), $:,
        z_convert:to_binary(Token), $:,
        z_convert:to_binary(Secret), $:,
        z_convert:to_binary(ValidFor)
    ].

get_q_all(Context) ->
    Args = z_context:get_q_all_noz(Context),
    case z_context:get_q(<<"*">>, Context) of
        undefined -> Args;
        Path -> [ {<<"*">>, Path} | Args ]
    end.

flatten_args(Args) ->
    [ [ K, 0, V, 0 ] || {K, V} <- filter_args(Args, []) ].

filter_args([], Acc) ->
    lists:sort(Acc);
filter_args([Token|Args], Acc) when is_atom(Token) ->
    filter_args([{z_convert:to_binary(Token),<<"true">>}|Args], Acc);
filter_args([{<<"z_access_url", _/binary>>,_}|Args], Acc) ->
    filter_args(Args, Acc);
filter_args([{<<"z_language">>,_}|Args], Acc) ->
    filter_args(Args, Acc);
filter_args([{<<"zotonic_", _/binary>>,_}|Args], Acc) ->
    filter_args(Args, Acc);
filter_args([{z_access_url,_}|Args], Acc) ->
    filter_args(Args, Acc);
filter_args([{absolute_url,_}|Args], Acc) ->
    filter_args(Args, Acc);
filter_args([{z_language,_}|Args], Acc) ->
    filter_args(Args, Acc);
filter_args([{zotonic_dispatch,_}|Args], Acc) ->
    filter_args(Args, Acc);
filter_args([{zotonic_dispatch_path,_}|Args], Acc) ->
    filter_args(Args, Acc);
filter_args([{zotonic_dispatch_path_rewrite,_}|Args], Acc) ->
    filter_args(Args, Acc);
filter_args([{star, V}|Args], Acc) ->
    V1 = z_convert:to_binary( cow_qs:urldecode(V) ),
    filter_args(Args, [{<<"*">>,V1}|Acc]);
filter_args([{<<"*">>, V}|Args], Acc) ->
    V1 = z_convert:to_binary( cow_qs:urldecode(V) ),
    filter_args(Args, [{<<"*">>,V1}|Acc]);
filter_args([{K,V}|Args], Acc) ->
    K1 = z_convert:to_binary(K),
    case K1 of
        <<"z_access_url", _/binary>> ->
            filter_args(Args, Acc);
        <<"*">> ->
            V1 = z_convert:to_binary(V),
            filter_args(Args, [{<<"star">>,V1}|Acc]);
        _ ->
            V1 = z_convert:to_binary(V),
            filter_args(Args, [{K1,V1}|Acc])
    end.

%% Outlook.com decodes and re-combines urls without doing percent-encoding.
fix_outlook_sig(Sig) ->
    binary:replace(Sig, <<" ">>, <<"+">>, [ global ]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

signature_compatibility_test() ->
    Args = [{<<"id">>, <<"123">>}],
    Data = signed_data(page, Args, <<"token">>, <<"nonce">>, <<"secret">>, undefined),
    Hash = crypto:hash(sha256, Data),
    ?assertEqual({ok, base64url}, test_verify(base64url:encode(Hash), Args, undefined)),
    ?assertEqual({ok, base64}, test_verify(base64:encode(Hash), Args, undefined)),
    lists:foreach(
        fun({Minor, Format}) ->
            Sig = test_historical_signature(Args, Minor),
            ?assertEqual({ok, Format}, test_verify(Sig, Args, undefined)),
            ?assertEqual({ok, Format}, test_verify(Sig, Args, <<>>)),
            ?assertEqual({error, signature_mismatch}, test_verify(Sig, Args, <<"2000000000">>)),
            ?assertEqual({error, signature_mismatch}, test_verify(Sig, [{<<"id">>, <<"124">>}], undefined)),
            ?assertEqual({error, signature_mismatch}, verify_signature(Sig, other_page, Args,
                <<"token">>, <<"nonce">>, <<"secret">>, undefined)),
            ?assertEqual({error, signature_mismatch}, verify_signature(Sig, page, Args,
                <<"token">>, <<"nonce">>, <<"wrong-secret">>, undefined)),
            ?assertEqual({error, signature_mismatch}, verify_signature(Sig, page, Args,
                <<"token">>, <<"other-nonce">>, <<"secret">>, undefined))
        end,
        [{1, legacy_term_v1}, {2, legacy_term_v2}]),
    OldArgs = lists:sort([{<<"use_absolute_url">>, <<"true">>} | Args]),
    OldSig = test_historical_signature(OldArgs, 1),
    ?assertEqual({ok, legacy_use_absolute_url}, test_verify(OldSig, Args, undefined)),
    ?assertEqual({error, signature_mismatch}, test_verify(OldSig, Args, <<"2000000000">>)).

%% Reproduce the old encoder independently of the compatibility helpers.
test_historical_signature(Args, Minor) ->
    base64:encode(crypto:hash(sha256, term_to_binary(
        [Args, signed, <<"page">>, <<"nonce">>, <<"token">>, <<"secret">>],
        [{minor_version, Minor}]))).

test_verify(Sig, Args, Expiry) ->
    verify_signature(Sig, page, Args, <<"token">>, <<"nonce">>, <<"secret">>, Expiry).

signature_arguments_test() ->
    Sent = [{<<"id">>, <<"123">>}],
    Original = [{id,123}, {empty,<<>>}, {missing,undefined}, {list,[]},
        absolute_url, {absolute_url,true}, {zotonic_http_accept,<<"application/pdf">>}],
    Sig = encode_v1(signed_data(page, transmitted_args(Original),
        <<"token">>, <<"nonce">>, <<"secret">>, undefined)),
    ?assertEqual({ok, base64url}, test_verify(Sig, Sent, undefined)),
    ?assertEqual({error, signature_mismatch}, test_verify(Sig, Sent ++ [{<<"empty">>, <<>>}], undefined)),
    ?assertEqual({error, signature_mismatch}, test_verify(Sig, Sent ++ [{<<"utm_source">>, <<"mail">>}], undefined)),
    Encoded = [{<<"value">>, unicode:characters_to_binary("a + b / 50% café & x=y")}],
    RoundTrip = cow_qs:parse_qs(cow_qs:qs(Encoded)),
    Sig1 = encode_v1(signed_data(page, Encoded, <<"token">>, <<"nonce">>, <<"secret">>, undefined)),
    ?assertEqual({ok, base64url}, test_verify(Sig1, RoundTrip, undefined)).

expiry_query_option_test() ->
    ?assertEqual(<<"/page/123">>, remove_expiry_arg(<<"/page/123?z_access_url_valid_for=3600">>)),
    ?assertEqual(<<"/page/123?id=123&x=a%26b">>,
        remove_expiry_arg(<<"/page/123?id=123&z_access_url_valid_for=3600&x=a%26b">>)),
    ?assertEqual(<<"/page/123?id=123&amp;x=a%26b">>,
        remove_expiry_arg(<<"/page/123?id=123&amp;z_access_url_valid_for=%2Bday&amp;x=a%26b">>)).

signature_expiry_test() ->
    Args = [{<<"id">>, <<"123">>}],
    Expiry = integer_to_binary(z_datetime:timestamp() + 3600),
    Sig = encode_v1(signed_data(page, Args, <<"token">>, <<"nonce">>, <<"secret">>, Expiry)),
    ?assertEqual({ok, base64url}, test_verify(Sig, Args, Expiry)),
    ?assertEqual({error, signature_mismatch}, test_verify(Sig, Args, undefined)),
    ?assertEqual(valid, expiry_status(Expiry)),
    ?assertEqual(expired, expiry_status(<<"1">>)),
    ?assertEqual(invalid_expiry, expiry_status(<<"not-a-date">>)),
    ?assertEqual({error, malformed_signature}, test_verify(<<>>, Args, undefined)),
    ?assertEqual({error, malformed_signature}, test_verify(binary:copy(<<"x">>, 10000), Args, undefined)).

signature_outlook_test() ->
    % Find a deterministic test nonce whose old Base64 signature contains '+'.
    {Nonce, Sig} = hd([
        {N, S}
        || I <- lists:seq(1, 100),
           N <- [integer_to_binary(I)],
           S <- [base64:encode(crypto:hash(sha256,
               signed_data(page, [], <<"token">>, N, <<"secret">>, undefined)))],
           binary:match(S, <<"+">>) =/= nomatch
    ]),
    Damaged = binary:replace(Sig, <<"+">>, <<" ">>, [global]),
    ?assertEqual({ok, base64}, verify_signature(Damaged, page, [],
        <<"token">>, Nonce, <<"secret">>, undefined)).

-endif.
