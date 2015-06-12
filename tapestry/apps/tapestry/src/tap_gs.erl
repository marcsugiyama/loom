% tapestry's interface to the graph store
%
% Store a list of vertices and edges in mnesia.  Also store the graph
% in dobby.  Use dobby to store the labels/metadata for the vertices
% and edges.
%
-module(tap_gs).

-include("tap_mnesia.hrl").

-define(PUBLISHER, <<"tapestry">>).

-export([
    clear/0,
    vertex/1,
    add_vertex/2,
    update_vertex/2,
    edge/1,
    add_edge/2,
    no_vertices/0,
    no_edges/0,
    del_vertices/1,
    del_edges/1,
    vertices/0,
    edges/0
]).

% Erase store
clear() ->
    tap_mnesia:clear(),
% XXX running dobby remotely
%   dby_db:clear(),
    ok.

% Get vertex metadata (returns metadata_info()).
vertex(Vertex) ->
    dby:identifier(identifier_name(Vertex)).

% Add vertex
% Metadata is a property list
add_vertex(Vertex, Metadata) ->
    IdentifierName = identifier_name(Vertex),
    ok = tap_mnesia:insert(#vertex{vertex = Vertex,
                                   metadata = Metadata}),
    ok = publish({IdentifierName, Metadata}).

% Update edge
% Metadata is a property list
update_vertex(Vertex, Metadata) ->
    ok = publish({identifier_name(Vertex), Metadata}).

% Get edge metadata
edge({A, B}) ->
    dby:link_metadata(identifier_name(A), identifier_name(B)).

% Add edge/update
% Metadata is a property list
add_edge({{A, MA}, {B, MB}}, Metadata) ->
    IDA = identifier_name(A),
    IDB = identifier_name(B),
    ok = tap_mnesia:insert(#vertex{vertex = A,
                                   metadata = MA}),
    ok = tap_mnesia:insert(#vertex{vertex = B,
                                   metadata = MB}),
    ok = tap_mnesia:insert(#edge{edge = normal_edge(A, B),
                                 metadata = Metadata}),
    ok = publish({{IDA, MA}, {IDB, MB}, Metadata}).

% Number of vertices
no_vertices() ->
    tap_mnesia:size(vertex).

% Number of edges
no_edges() ->
    tap_mnesia:size(edge).

% Delete Vertices
del_vertices(Vertices) ->
    ok = tap_mnesia:deletes(vertex, Vertices),
    delete_stranded_edges(Vertices),
    Delete = [{V, delete} || V <- Vertices],
    ok = publish(Delete).

% Delete Edges
del_edges(Edges) ->
    ok = tap_mnesia:delete(edge, Edges),
    Delete = [{A, B, delete} || {A, B} <- Edges],
    ok = publish(Delete).

% List of vertices
vertices() ->
    [Vertex || #vertex{vertex = Vertex} <- tap_mnesia:selectall(vertex)].

% List of edges
edges() ->
    [Edge || #edge{edge = Edge} <- tap_mnesia:selectall(edge)].

%-------------------------------------------------------------------------------
% helper functions
%-------------------------------------------------------------------------------

publish(Item) ->
    ok = dby:publish(?PUBLISHER, Item, [persistent]).

identifier_name(A = {_,_,_,_}) ->
    list_to_binary(inet:ntoa(A));
identifier_name(A = {_,_,_,_,_,_,_,_}) ->
    list_to_binary(inet:ntoa(A));
identifier_name(B) when is_binary(B) ->
    B;
identifier_name(S) when is_list(S) ->
    list_to_binary(S);
identifier_name(U) ->
    iolist_to_binary(io_lib:format("~p", [U])).

normal_edge(A, B) when A > B ->
    {A, B};
normal_edge(A, B) ->
    {B, A}.

delete_stranded_edges(Vertices) ->
    VerticesSet = sets:from_list(Vertices),
    Edges = lists:foldl(
        fun(#edge{edge = Edge = {A, B}}, Acc) ->
            case sets:is_element(A, VerticesSet) orelse
                    sets:is_element(B, VerticesSet) of
                true ->
                    [Edge | Acc];
                false ->
                    Acc
            end
        end, [], edges()),
    tap_mnesia:deletes(edge, Edges).
