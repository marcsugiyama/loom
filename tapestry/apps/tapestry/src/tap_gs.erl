% tapestry's interface to the graph store
%
% Store a list of vertices and edges in mnesia.  Also store the graph
% in dobby.  Use dobby to store the labels/metadata for the vertices
% and edges.
%
-module(tap_gs).

-include("tap_mnesia.hrl").

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
    values(tap_dobby:endpoint(Vertex)).

% Add vertex
% Metadata is a property list
add_vertex(Vertex, Metadata) ->
    IdentifierName = tap_dobby:endpoint_name(Vertex),
    ok = tap_mnesia:insert(#vertex{vertex = Vertex,
                                   metadata = Metadata}),
    ok = tap_dobby:publish({IdentifierName,
            [{<<"type">>, <<"tapestry-identifier">>} | Metadata]}).

% Update edge
% Metadata is a property list
update_vertex(Vertex, Metadata) ->
    ok = tap_dobby:publish({tap_dobby:endpoint_name(Vertex), Metadata}).

% Get edge metadata
edge(Edge) ->
    values(tap_dobby:edge(Edge)).

% Add edge/update
% Metadata is a property list
add_edge({{A, MA}, {B, MB}}, Metadata) ->
    ok = tap_mnesia:insert(#vertex{vertex = A, metadata = MA}),
    ok = tap_mnesia:insert(#vertex{vertex = B, metadata = MB}),
    ok = tap_mnesia:insert(#edge{edge = normal_edge(A, B),
                                                     metadata = Metadata}),
    ok = tap_dobby:publish(tap_dobby:endpoint_link(A, MA, B, MB, Metadata)).

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
    ok = tap_dobby:delete_endpoints(Vertices).

% Delete Edges
del_edges(Edges) ->
    ok = tap_mnesia:deletes(edge, Edges),
    ok = tap_dobby:delete_edges(Edges).

% List of vertices
vertices() ->
    [Vertex || #vertex{vertex = Vertex} <- tap_mnesia:selectall(vertex)].

% List of edges
edges() ->
    [Edge || #edge{edge = Edge} <- tap_mnesia:selectall(edge)].

%-------------------------------------------------------------------------------
% helper functions
%-------------------------------------------------------------------------------

normal_edge(A, B) when A > B ->
    {A, B};
normal_edge(A, B) ->
    {B, A}.

delete_stranded_edges(Vertices) ->
    VerticesSet = sets:from_list(Vertices),
    Edges = lists:foldl(
        fun(Edge = {A, B}, Acc) ->
            case sets:is_element(A, VerticesSet) orelse
                    sets:is_element(B, VerticesSet) of
                true ->
                    [Edge | Acc];
                false ->
                    Acc
            end
        end, [], edges()),
    tap_mnesia:deletes(edge, Edges).

% extract value from identifier metdata info
values(Map) ->
    maps:map(
        fun(_, #{value := Value}) ->
            Value
        end, Map).
