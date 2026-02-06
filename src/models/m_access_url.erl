%% @author Marc Worrell <marc@worrell.nl>
%% @copyright 2026 Marc Worrell
%% @doc Model to generate access URLs for resources.
%% @end

-module(m_access_url).

-export([
    m_get/3,

    generate_url/2,
    generate_url/3
]).


m_get([ <<"generate">> | Rest ], #{ payload := Payload }, Context) ->
    Id = maps:get(<<"id">>, Payload, undefined),
    ValidFor = maps:get(<<"valid_for">>, Payload, undefined),
    case generate_url(Id, ValidFor, Context) of
        undefined ->
            {error, invalid};
        Url ->
            Url1 = binary:replace(Url, <<"&amp;">>, <<"&">>, [global]),
            {ok, {Url1, Rest}}
    end;
m_get([ <<"reload_needed">> | Rest ], _Msg, Context) ->
    % The access URLs need a cotonic session id to function.
    % Reload the page till we receive a session cookie from cotonic.
    IsReloadNeeded = case z_context:is_request(Context) of
        true ->
            case z_context:get(is_z_access_url, Context) of
                true ->
                    case z_context:get_cookie(<<"cotonic-sid">>, Context) of
                        undefined ->
                            case z_context:get_controller_module(Context) of
                                controller_page -> true;
                                controller_template -> true;
                                _ -> false
                            end;
                        _SessionId ->
                            false
                    end;
                _ ->
                    false
            end;
        false ->
            ok
    end,
    {ok, {IsReloadNeeded, Rest}}.


generate_url(Id, Context) ->
    generate_url(Id, undefined, Context).

generate_url(undefined, _ValidFor, _Context) ->
    undefined;
generate_url(Id, ValidFor, Context) when is_integer(Id) ->
    case z_auth:is_auth(Context) of
        true ->
            ExtraArgs = [
                {z_access_url, true},
                {z_access_url_valid_for, ValidFor}
            ],
            Context1 = z_context:set(ExtraArgs, Context),
            m_rsc:p(Id, <<"page_url_abs">>, Context1);
        false ->
            undefined
    end;
generate_url(Id, ValidFor, Context) ->
    generate_url(m_rsc:rid(Id, Context), ValidFor, Context).

