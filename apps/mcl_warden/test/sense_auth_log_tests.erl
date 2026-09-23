%%% @doc Following the auth log across rotation.
%%%
%%% On 2026-07-26 every warden in the fleet went silent at once and stayed
%%% silent for two days, while the boxes were still being attacked and every
%%% container still reported healthy. logrotate had replaced auth.log and the
%%% sensor never noticed. These tests pin the noticing.
-module(sense_auth_log_tests).
-include_lib("eunit/include/eunit.hrl").
-include("../src/sense_auth_log/sense_auth_log.hrl").

%% Below ?THRESHOLD (5), so a sighting is counted but never published: these
%% tests are about reading the file, not about reaching the mesh.
-define(BELOW_THRESHOLD, 4).

rotation_test_() ->
    {foreach, fun setup/0, fun cleanup/1,
     [fun replacement_larger_than_our_position_is_followed/1,
      fun truncation_in_place_is_followed/1,
      fun history_before_the_first_open_is_ignored/1]}.

setup() ->
    Dir = filename:join(["/tmp", "sense-auth-log-" ++ integer_to_list(erlang:unique_integer([positive]))]),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    Path = filename:join(Dir, "auth.log"),
    ok = file:write_file(Path, <<>>),
    ok = application:set_env(mcl_warden, auth_log, Path),
    {ok, Pid} = sense_auth_log:start_link(),
    %% Settle the open that `init' schedules BEFORE any test writes a line.
    %% Otherwise the first open races the first append and lands at an EOF that
    %% is already past it, which looks exactly like the bug under test.
    poll(),
    #{dir => Dir, path => Path, pid => Pid}.

%% One test deliberately restarts the sensor, so stop whatever answers to the
%% registered name now rather than the pid setup happened to create.
cleanup(#{dir := Dir}) ->
    stop(whereis(sense_auth_log)),
    _ = os:cmd("rm -rf " ++ Dir),
    ok.

stop(undefined) -> ok;
stop(Pid)       -> gen_server:stop(Pid).

%% THE REGRESSION. The sensor used to decide "this file was rotated" purely
%% from the size at the path being smaller than its own read position. A
%% replacement that is already LARGER than that position defeats it entirely,
%% and on a box taking tens of thousands of attempts a day the replacement gets
%% there within seconds. The inode is what actually changed.
replacement_larger_than_our_position_is_followed(#{path := Path}) ->
    fun() ->
        %% Read a little, so our position is small.
        append(Path, failed_auth_lines(<<"203.0.113.10">>, 1)),
        poll(),
        ?assertEqual(1, sightings(<<"203.0.113.10">>)),

        %% Rotate: rename ours away, put a DIFFERENT and BIGGER file in its
        %% place. Size alone cannot see this; the inode can.
        ok = file:rename(Path, Path ++ ".1"),
        ok = file:write_file(Path, padding(4096)),
        append(Path, failed_auth_lines(<<"198.51.100.20">>, ?BELOW_THRESHOLD)),
        ?assert(filelib:file_size(Path) > position()),

        poll(),
        ?assertEqual(?BELOW_THRESHOLD, sightings(<<"198.51.100.20">>))
    end.

%% logrotate `copytruncate' keeps the inode and empties the file, so only the
%% size check can see it. It sees it while the emptied file is still shorter
%% than our position, which at a 2s poll and real log rates is always: the
%% public boxes write ~230 bytes per poll against a position of tens of MB.
%% A file that regrew PAST our position inside one poll would be missed, which
%% is a property of size-based detection and the reason the inode check carries
%% the rename case rather than this one.
truncation_in_place_is_followed(#{path := Path}) ->
    fun() ->
        append(Path, failed_auth_lines(<<"203.0.113.30">>, ?BELOW_THRESHOLD)),
        poll(),
        ?assertEqual(?BELOW_THRESHOLD, sightings(<<"203.0.113.30">>)),
        Before = position(),

        ok = file:write_file(Path, <<>>),
        append(Path, failed_auth_lines(<<"198.51.100.40">>, 1)),
        ?assert(filelib:file_size(Path) < Before),

        poll(),
        ?assertEqual(1, sightings(<<"198.51.100.40">>))
    end.

%% We tail for live attacks. Whatever was already in the file when we first
%% opened it is history and must not be replayed as a fresh sighting. Restarting
%% the sensor against a log full of yesterday's attacks must report nothing.
history_before_the_first_open_is_ignored(#{path := Path, pid := Pid}) ->
    fun() ->
        gen_server:stop(Pid),
        append(Path, failed_auth_lines(<<"203.0.113.50">>, 50)),
        {ok, _} = sense_auth_log:start_link(),
        poll(),
        ?assertEqual(0, sightings(<<"203.0.113.50">>)),

        %% ...but a line written after that open is live, and is counted.
        append(Path, failed_auth_lines(<<"203.0.113.50">>, 2)),
        poll(),
        ?assertEqual(2, sightings(<<"203.0.113.50">>))
    end.

%% --- helpers ---

%% The gen_server polls on a timer; nudging it and then making a synchronous
%% call guarantees the poll ahead of us in the mailbox has been handled.
poll() ->
    sense_auth_log ! poll,
    _ = sys:get_state(sense_auth_log),
    ok.

state() -> sys:get_state(sense_auth_log).

sightings(Ip) -> length(maps:get(Ip, (state())#st.hits, [])).

position() -> (state())#st.pos.

append(Path, Data) ->
    {ok, Fd} = file:open(Path, [append, binary, raw]),
    ok = file:write(Fd, Data),
    ok = file:close(Fd).

failed_auth_lines(Ip, N) ->
    iolist_to_binary(
      [["Jul 28 04:00:00 host sshd[1]: Failed password for root from ",
        Ip, " port 4021 ssh2\n"] || _ <- lists:seq(1, N)]).

%% Unparseable filler, purely to make the replacement file big.
padding(Bytes) ->
    iolist_to_binary(lists:duplicate(Bytes div 32, <<"Jul 28 04:00:00 host cron: noise\n">>)).
