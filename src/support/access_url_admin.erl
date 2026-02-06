%% @author Marc Worrell <marc@worrell.nl>
%% @copyright 2026 Marc Worrell
%% @doc Generate the access URL to the given resource. The generated
%% link allows anyone to view the resource and all resources shown on it
%% using the permissions of the current user.
%% @end

%% Copyright 2026 Marc Worrell
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

-module(access_url_admin).

-export([
    event/2
]).

-include_lib("zotonic_core/include/zotonic.hrl").

event(#postback{ message = {share_link, Args} }, Context) ->
    {id, Id} = proplists:lookup(id, Args),
    {element_id, EltId} = proplists:lookup(element_id, Args),
    case z_acl:rsc_visible(Id, Context) andalso z_auth:is_auth(Context) of
        true ->
            ValidFor = proplists:get_value(valid_for, Args),
            case m_access_url:generate_url(Id, ValidFor, Context) of
                undefined ->
                    Context1 = z_render:update(EltId, <<>>, Context),
                    z_render:growl(?__("Could not generate the URL to share this resource", Context), Context1);
                Url ->
                    z_render:update(EltId, z_html:ensure_escaped_amp(Url), Context)
            end;
        false ->
            Context1 = z_render:update(EltId, <<>>, Context),
            z_render:growl(?__("You don't have permission to share this resource", Context), Context1)
    end.
