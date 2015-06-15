-module(tap_dobby).

-define(PUBLISHER, <<"tapestry">>).

-export([
    publish/1,
    endpoint/1,
    edge/1,
    endpoint_name/1,
    endpoint_link/5,
    community_name/1,
    community_endpoint_link/2
]).

publish(Item) ->
    ok = dby:publish(?PUBLISHER, Item, [persistent]).

endpoint(Endpoint) ->
    dby:identifier(endpoint_name(Endpoint)).

edge({A, B}) ->
    dby:link_metadata(endpoint_name(A), endpoint_name(B)).

endpoint_name(Endpoint) ->
    iolist_to_binary([<<"endpoint-">>, format_identifier(Endpoint)]).

endpoint_link(A, MA, B, MB, Metadata) ->
    {{endpoint_name(A), [{<<"type">>, <<"tapestry-identifier">>} | MA]},
     {endpoint_name(B), [{<<"type">>, <<"tapestry-identifier">>} | MB]},
     [{<<"type">>, <<"activity">>} | Metadata]}.

community_endpoint_link(Community, Vertex) ->
    {{community_name(Community), [{<<"type">>, <<"tapestry-community">>}]},
     endpoint_name(Vertex),
     [{<<"type">>, <<"member_of">>}]}.

community_name(Community) ->
    iolist_to_binary([<<"communitiy-">>, format_identifier(Community)]).

% helpers

format_identifier(A = {_,_,_,_}) ->
    list_to_binary(inet:ntoa(A));
format_identifier(A = {_,_,_,_,_,_,_,_}) ->
    list_to_binary(inet:ntoa(A));
format_identifier(B) when is_binary(B) ->
    B;
format_identifier(S) when is_list(S) ->
    list_to_binary(S);
format_identifier(U) ->
    iolist_to_binary(io_lib:format("~p", [U])).
