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

-author("Marc Worrell <marc@worrell.nl>").

-mod_title("Access URL").
-mod_description("Sign an URL for an user so that it can be used for accessing vcal feeds etc.").
-mod_prio(300).

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
%% images might not be visible on pages that are accessed with an access url becaus
%% the image resources are not visible to the logged on user.
%%
%% If the `z_access_url` argument is set on the URL, then a token will be added to
%% URL for the current user.
observe_url_rewrite(#url_rewrite{ dispatch = image, args = Args }, Url, Context) ->
    case z_context:get(is_z_access_url, Context) of
        true ->
            maybe_add_token(image, Args, Url, Context);
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
    case z_acl:user(Context) of
        undefined ->
            Url;
        UserId when is_integer(UserId) ->
            ValidFor = z_convert:to_binary(valid_for(Args, Context)),
            {ok, Token, Secret} = user_secret(UserId, Context),
            Nonce = z_ids:id(),
            SignedData = signed_data(Dispatch, Args, Token, Nonce, Secret, ValidFor),
            Sig = encode_v1(SignedData),
            ExtraArgs = <<"z_access_url_token=", Token/binary,
                          "&z_access_url_nonce=", Nonce/binary,
                          "&z_access_url_sig=", Sig/binary>>,
            ExtraArgs1 = if
                ValidFor =:= <<>> -> ExtraArgs;
                true -> <<ExtraArgs/binary, "&z_access_url_valid_for=", ValidFor/binary>>
            end,
            case binary:match(Url, <<"?">>) of
                nomatch -> <<Url/binary, $?, ExtraArgs1/binary>>;
                _ -> <<Url/binary, $&, ExtraArgs1/binary>>
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
            % Ignore
            Context;
        _ ->
            Token = z_convert:to_binary(z_context:get_q(<<"z_access_url_token">>, Context)),
            case token_user(Token, Context) of
                {ok, UserId, Secret} ->
                    Nonce = z_context:get_q(<<"z_access_url_nonce">>, Context),
                    ValidFor = z_context:get_q(<<"z_access_url_valid_for">>, Context),
                    Dispatch = z_context:get_q(<<"zotonic_dispatch">>, Context),
                    Sig = z_convert:to_binary(z_context:get_q(<<"z_access_url_sig">>, Context)),
                    case is_valid_signature(Sig, Dispatch, get_q_all(Context), Token, Nonce, Secret, ValidFor) of
                        true ->
                            case is_valid_for(ValidFor) of
                                true ->
                                    ?LOG_DEBUG(#{
                                        in => zotonic_mod_access_url,
                                        text => <<"Valid url_access_token signature on request">>,
                                        result => ok,
                                        user_id => UserId,
                                        path => cowmachine_req:raw_path(Context)
                                    }),
                                    Context1 = z_context:set(is_z_access_url, true, Context),
                                    UserContext = z_acl:logon(UserId, z_context:new(Context)),
                                    Context2 = z_context:set(z_access_url_context, UserContext, Context1),
                                    z_context:set_noindex_header(true, Context2);
                                false ->
                                    ?LOG_INFO(#{
                                        in => zotonic_mod_access_url,
                                        text => <<"Expired url_access_token signature on request">>,
                                        result => error,
                                        reason => signature_mismatch,
                                        token => Token,
                                        user_id => UserId,
                                        valid_for => ValidFor,
                                        now => z_datetime:timestamp(),
                                        path => cowmachine_req:raw_path(Context)
                                    }),
                                    Context
                            end;
                        false ->
                            ?LOG_WARNING(#{
                                in => zotonic_mod_access_url,
                                text => <<"Invalid url_access_token signature on request">>,
                                result => error,
                                reason => signature_mismatch,
                                token => Token,
                                user_id => UserId,
                                path => cowmachine_req:raw_path(Context)
                            }),
                            Context
                    end;
                {error, enoent} ->
                    ?LOG_INFO(#{
                        in => zotonic_mod_access_url,
                        text => <<"Unknown url_access_token">>,
                        result => error,
                        reason => unknown_user_token,
                        token => Token
                    }),
                    Context
            end
    end.

is_valid_signature(Sig, Dispatch, Args, Token, Nonce, Secret, ValidFor) ->
    Sig1 = fix_outlook_sig(Sig),
    Data = signed_data(Dispatch, Args, Token, Nonce, Secret, ValidFor),
    case encode_v1(Data) of
        Sig -> true;
        Sig1 -> true;
        _ ->
            case encode_v2(Data) of
                Sig -> true;
                Sig1 -> true;
                _ ->
                    % Check for old signatures which used term_to_binary/2
                    % for the serialization of the signed data.
                    HashedData_v1 = hash_term_v1(Data),
                    case encode_v2(HashedData_v1) of
                        Sig -> true;
                        Sig1 -> true;
                        _ ->
                            HashedData_v2 = hash_term_v2(Data),
                            case encode_v2(HashedData_v2) of
                                Sig -> true;
                                Sig1 -> true;
                                _ -> false
                            end
                    end
            end
    end.

is_valid_for(undefined) ->
    true;
is_valid_for(<<>>) ->
    true;
is_valid_for(ValidFor) ->
    try
        ValidForInt = z_convert:to_integer(ValidFor),
        ValidForInt >= z_datetime:timestamp()
    catch
        _:_ -> false
    end.

encode_v1(Data) ->
    base64url:encode(crypto:hash(sha256, Data)).

encode_v2(Data) ->
    base64:encode(crypto:hash(sha256, Data)).

hash_term_v1(SignedData) ->
    Data = term_to_binary(SignedData, [ {minor_version, 1} ]),
    crypto:hash(sha256, Data).

hash_term_v2(SignedData) ->
    Data = term_to_binary(SignedData, [ {minor_version, 1} ]),
    crypto:hash(sha256, Data).

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
