%% @author Marc Worrell <marc@worrell.nl>
%% @copyright 2026 Marc Worrell
%% @doc Model to generate access URLs for resources.
%% @end

-module(m_access_url).

-moduledoc(#{
    zotonic_keywords => [
        "reference", "model", "backend_developer", "frontend_developer",
        "authorization_and_access_control", "security", "url"
    ]
}).
-moduledoc("
Generate absolute resource page URLs signed with the current user's view
permissions. Requires `mod_access_url` to be enabled. Opening the link does not
log the recipient in as the signer; see `mod_access_url` for permissions,
embedded images, expiry and session grants.

## Model paths

### `generate`

Accepts a payload map with binary keys:

| Key | Meaning |
| --- | --- |
| `id` | Resource ID, name or another reference accepted by `m_rsc:rid/2`. |
| `valid_for` | Optional integer duration in seconds or binary date expression such as `+day`. Omit for no expiry. |

For example, the admin sharing widget calls this model through Cotonic:

```javascript
cotonic.broker.call(
    \"bridge/origin/model/access_url/get/generate\",
    {id: 123, valid_for: 3600}
).then(msg => console.log(msg.payload.result));
```

The result is the signed URL, with HTML `&amp;` separators converted to `&` for
use outside template markup. The model callback returns `{ok, {Url, Rest}}` or
`{error, invalid}` when URL generation returns `undefined`.

Generation requires an authenticated caller and reads the resource property
`page_url_abs`, which is available without a resource view check. The model does
not separately require view or edit permission to generate a URL. Access when
the link is opened is still limited by the signer's view permissions. The admin
widget additionally checks resource visibility before offering link generation.
Treat generated URLs as access credentials.

### `reload_needed`

```django
{% if m.access_url.reload_needed %}
    {% wire action={reload} %}
{% endif %}
```

Returns a boolean. It is true only for a validated access-URL HTTP request handled
by `controller_page` or `controller_template` without a `cotonic-sid` cookie.
Outside an HTTP request it is false. The module's `_html_body.tpl` already uses
this path to establish the browser session needed for subsequent resource grants.

## Erlang API

```erlang
Url = m_access_url:generate_url(Id, Context),
TemporaryUrl = m_access_url:generate_url(Id, 3600, Context).
```

`generate_url/2` omits expiry; `generate_url/3` accepts the same `valid_for` values
as the model payload. Both return a URL or `undefined` when there is no resource
URL or the caller is not authenticated. These functions use the same permission
checks as the model path. They do not perform the model callback's `&amp;`
normalization.
").

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
            false
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

