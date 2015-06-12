% tapestry's interface to mnesia
%
-module(tap_mnesia).

-export([
    start/0,
    clear/0,
    insert/1,
    size/1,
    deletes/2,
    selectall/1
]).

-include("tap_mnesia.hrl").

% start mnesia and create the on disk schema and tables if
% they don't already exist.
start() ->
    ok = mnesia:start(),
    schema(),
    tables().

clear() ->
    lists:foreach(
        fun({Name, _}) ->
            {atomic, ok} = mnesia:clear_table(Name)
        end,
    tabledefs()).

insert(Value) ->
    {atomic, ok} = mnesia:transaction(fun() -> mnesia:write(Value) end),
    ok.

size(Table) ->
    mnesia:table_info(Table, size).

deletes(Table, Keys) ->
    Delete = fun() ->
        lists:foreach(fun(Key) -> mnesia:delete({Table, Key}) end, Keys)
    end,
    {atomic, ok} = mnesia:transaction(Delete),
    ok.

selectall(Table) ->
    SelectAll = fun() ->
        mnesia:foldl(fun(Value, Acc) -> [Value | Acc] end, [], Table)
    end,
    {atomic, Values} = mnesia:transaction(SelectAll),
    Values.

%-------------------------------------------------------------------------------
% helper functions
%-------------------------------------------------------------------------------

schema() ->
    case disc_schema() of
        true ->
            ok;
        false ->
            % schema isn't on disk.  assume this is an initial setup
            % and move the schema to disk.
            {atomic, ok} = mnesia:change_table_copy_type(
                                                schema, node(), disc_copies)
    end,
    ok.

% is the schema on disk?
disc_schema() ->
    case mnesia:table_info(schema, disc_copies) of
        [] -> false;
        _ -> true
    end.

% create tables
tables() ->
    Tables = mnesia:system_info(tables),
    lists:foreach(fun({Name, TabDef}) ->
        case lists:member(Name, Tables) of
            true ->
                % table already exists
                ok;
            false ->
                % create the table
                {atomic, ok} = mnesia:create_table(Name, TabDef)
        end
    end, tabledefs()),
    ok.

tabledefs() ->
    % [{TableName, TableDef}]
    [
        {vertex, [{attributes, record_info(fields, vertex)},
                      {disc_copies, [node()]},
                      {type, set}]},
        {edge, [{attributes, record_info(fields, edge)},
                      {disc_copies, [node()]},
                      {type, set}]}
    ].
