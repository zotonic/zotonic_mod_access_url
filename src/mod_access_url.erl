%% @author Marc Worrell <marc@worrell.nl>
%% @copyright 2014-2024 Marc Worrell
%% @doc Access an url with the credentials of another user.
%% @end

%% Copyright 2014-2024 Marc Worrell
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

-export([
    observe_url_rewrite/3,
    observe_request_context/3
    ]).

-include_lib("kernel/include/logger.hrl").
-include_lib("zotonic_core/include/zotonic.hrl").

observe_url_rewrite(#url_rewrite{dispatch=image, args=Args}, Url, Context) ->
    case z_context:get(is_z_access_url, Context) of
        true ->
            maybe_add_token(image, Args, Url, Context);
        _False ->
            rewrite_if_access_url(image, Args, Url, Context)
    end;
observe_url_rewrite(#url_rewrite{dispatch=Dispatch, args=Args}, Url, Context) ->
    rewrite_if_access_url(Dispatch, Args, Url, Context).

rewrite_if_access_url(Dispatch, Args, Url, Context) ->
    case proplists:get_value(z_access_url, Args) of
        true ->
            maybe_add_token(Dispatch, Args, Url, Context);
        UserId when is_integer(UserId) ->
            maybe_add_token(Dispatch, Args, Url, z_acl:logon(UserId, Context));
        _ ->
            Url
    end.

observe_request_context(#request_context{ phase = refresh }, Context, _Context) ->
    case z_context:get_q(<<"z_access_url_token">>, Context) of
        undefined -> Context;
        <<>> -> Context;
        _ -> logon_if_sigok(Context)
    end;
observe_request_context(#request_context{ phase = _ }, Context, _Context) ->
    Context.

maybe_add_token(Dispatch, Args, Url, Context) ->
    case z_acl:user(Context) of
        undefined ->
            Url;
        UserId when is_integer(UserId) ->
            {ok, Token, Secret} = user_secret(UserId, Context),
            Nonce = z_convert:to_binary(z_ids:id()),
            Sig = sign(Dispatch, Args, Token, Nonce, Secret),
            Sig1 = z_convert:to_binary(cow_qs:urlencode(Sig)),
            ExtraArgs = <<"z_access_url_token=", Token/binary,
                          "&z_access_url_nonce=", Nonce/binary,
                          "&z_access_url_sig=", Sig1/binary>>,
            case binary:match(Url, <<"?">>) of
                nomatch ->
                    <<Url/binary, $?, ExtraArgs/binary>>;
                _ ->
                    <<Url/binary, $&, ExtraArgs/binary>>
            end
    end.

user_secret(UserId, Context) ->
    case m_identity:get_rsc_by_type(UserId, ?MODULE, Context) of
        [] ->
            Token = z_convert:to_binary(z_ids:id(20)),
            Secret = z_convert:to_binary(z_ids:id(40)),
            m_identity:insert(UserId, ?MODULE, Token, [{prop1, Secret}], Context),
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
                    Dispatch = z_context:get_q(<<"zotonic_dispatch">>, Context),
                    Sig = z_convert:to_binary(z_context:get_q(<<"z_access_url_sig">>, Context)),
                    case is_valid_signature(Sig, Dispatch, get_q_all(Context), Token, Nonce, Secret) of
                        true ->
                            Context1 = z_context:set(is_z_access_url, true, Context),
                            z_context:set_noindex_header(true, z_acl:logon(UserId, Context1));
                        false ->
                            ?LOG_WARNING(#{
                                in => zotonic_mod_access_url,
                                text => <<"Non matching signature on request">>,
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

is_valid_signature(Sig, Dispatch, Args, Token, Nonce, Secret) ->
    ArgsFiltered = filter_args(Args, []),
    Sig1 = fix_outlook_sig(Sig),
    case sign_args(Dispatch, ArgsFiltered, Token, Nonce, Secret) of
        Sig -> true;
        Sig1 -> true;
        _ ->
            % Check for the old versions which used term_to_binary for the signature generation.
            case sign_args_old_v1(Dispatch, ArgsFiltered, Token, Nonce, Secret) of
                Sig -> true;
                Sig1 -> true;
                _ ->
                    case sign_args_old_v2(Dispatch, ArgsFiltered, Token, Nonce, Secret) of
                        Sig -> true;
                        Sig1 -> true;
                        _ ->
                            % For a short time there was a version where (old) use_absolute_url
                            % was not filtered from the signature generation.
                            % Retry with the use_absolute_url argument to check for these
                            % wrongly generated signatures.
                            ArgsFiltered1 = lists:sort([{<<"use_absolute_url">>, <<"true">>}|ArgsFiltered]),
                            sign_args_old_v1(Dispatch, ArgsFiltered1, Token, Nonce, Secret) =:= Sig
                    end
            end
    end.


sign(Dispatch, Args, Token, Nonce, Secret) ->
    sign_args(Dispatch, filter_args(Args, []), Token, Nonce, Secret).

sign_args(Dispatch, Args, Token, Nonce, Secret) ->
    Data = iolist_to_binary([
                    flatten_args(Args), $:,
                    <<"signed:">>,
                    z_convert:to_binary(Dispatch), $:,
                    z_convert:to_binary(Nonce), $:,
                    z_convert:to_binary(Token), $:,
                    z_convert:to_binary(Secret)
                ]),
    base64:encode(crypto:hash(sha256, Data)).

flatten_args(Args) ->
    [ [ K, 0, V, 0 ] || {K, V} <- Args ].

%% Older versions used the term_to_binary version 1.
sign_args_old_v1(Dispatch, Args, Token, Nonce, Secret) ->
    Data = term_to_binary([
                    Args,
                    signed,
                    z_convert:to_binary(Dispatch),
                    z_convert:to_binary(Nonce),
                    z_convert:to_binary(Token),
                    z_convert:to_binary(Secret)
                ], [ {minor_version, 1} ]),
    base64:encode(crypto:hash(sha256, Data)).

%% Older versions used for a short time term_to_binary version 2 on OTP26
sign_args_old_v2(Dispatch, Args, Token, Nonce, Secret) ->
    Data = term_to_binary([
                    Args,
                    signed,
                    z_convert:to_binary(Dispatch),
                    z_convert:to_binary(Nonce),
                    z_convert:to_binary(Token),
                    z_convert:to_binary(Secret)
                ], [ {minor_version, 2} ]),
    base64:encode(crypto:hash(sha256, Data)).

get_q_all(Context) ->
    Args = z_context:get_q_all_noz(Context),
    case z_context:get_q(<<"*">>, Context) of
        undefined -> Args;
        Path -> [ {<<"*">>, Path} | Args ]
    end.

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
