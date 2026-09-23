%%% @doc The breadth sensor: read the host auth log, see every attacker.
%%%
%%% The tarpit catches the ones who probe our decoy ports; the real firehose is
%%% the box's actual sshd, taking tens of thousands of credential-spray attempts
%%% a day. We tail its log (mounted read-only from the host), count attempts per
%%% source IP in a rolling window, and when an IP crosses a threshold we publish
%%% an attacker_sighted fact. That is what lets the commons warn the next box:
%%% we measured a median 56-minute head start before the same attacker reaches
%%% it.
%%%
%%% Read-only. We parse log lines; we never touch sshd, and the warden cannot
%%% block anyone. It sees and it reports.
-module(sense_auth_log).
-include_lib("kernel/include/file.hrl").
-behaviour(gen_server).

-export([start_link/0, status/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).
-export([parse/1]).  %% exported for tests

%% A single fat-fingered login is not an attack. This many failures from one IP
%% inside the window is. Tuned to the real distribution on the public boxes: the
%% attackers are a broad, distributed botnet — many source IPs each at a low
%% rate (4-8 tries per 5 min) rather than a few hammering hard, so a high
%% threshold almost never fires. Five failed auths in five minutes from one IP
%% is unambiguously malicious here (it is credential spray, not a typo).
-define(THRESHOLD, 5).
-define(WINDOW_MS, 300000).      %% 5 minutes
-define(POLL_MS,   2000).
%% Don't re-report the same IP more often than this (it is still attacking).
-define(REPORT_COOLDOWN_MS, 600000).

-include("sense_auth_log.hrl").

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% @doc What this sensor is actually attached to, and whether it is still
%% reading. The warden's health depends on it: an auth-log tail that is alive
%% but blind reports nothing and looks identical to a quiet night, which is how
%% the fleet stayed silent for two days without a single alarm.
-spec status() -> #{path := string(),
                    attached := boolean(),
                    inode := non_neg_integer() | undefined,
                    pos := non_neg_integer(),
                    silent_ms := non_neg_integer() | undefined}.
status() ->
    gen_server:call(?MODULE, status, 1000).

init([]) ->
    Path = application:get_env(mcl_warden, auth_log, "/host/log/auth.log"),
    self() ! poll,
    {ok, #st{path = Path}}.

handle_call(status, _From, #st{} = St) ->
    {reply, snapshot(St), St};
handle_call(_Req, _From, St) -> {reply, {error, unknown_call}, St}.
handle_cast(_Msg, St)        -> {noreply, St}.

handle_info(poll, St) ->
    %% Drain what we hold BEFORE looking for a rotation: the tail of the
    %% outgoing file is still ours to read, and it stops growing the instant
    %% the new one appears. Then follow the path, then drain the new file.
    St2 = drain(follow(drain(St))),
    erlang:send_after(?POLL_MS, self(), poll),
    {noreply, St2};
handle_info(_Info, St) ->
    {noreply, St}.

terminate(_Reason, #st{fd = Fd}) ->
    _ = close(Fd),
    ok.

%% --- Internal ---

snapshot(#st{path = Path, fd = Fd, inode = Inode, pos = Pos, last_read_ms = Last}) ->
    #{path      => Path,
      attached  => Fd =/= undefined,
      inode     => Inode,
      pos       => Pos,
      silent_ms => silent_for(Last)}.

%% `undefined' is NOT zero silence: it means we have never read a byte, which
%% health/0 must not mistake for a sensor that has gone deaf.
silent_for(undefined) -> undefined;
silent_for(Last)      -> max(0, erlang:system_time(millisecond) - Last).

%% Open the log lazily, and FOLLOW IT ACROSS ROTATION.
%%
%% What rotates is the path, not the handle. logrotate renames auth.log to
%% auth.log.1 and creates a fresh one, so an open fd goes on pointing at a file
%% that will never grow again — the sensor sits at EOF forever and reports
%% nothing, while the box is still being attacked and the container still looks
%% healthy. That is exactly how the whole fleet went blind on 2026-07-26.
%%
%% We compare the INODE at the path against the one we opened. A size check
%% alone cannot see a rename: it only fires while the new file is still shorter
%% than our position, and on a box taking tens of thousands of attempts a day
%% the replacement passes that mark in seconds. The size check is kept for
%% truncation in place (logrotate `copytruncate'), where the inode does not
%% change.
%%
%% The mount matters as much as this code: bind-mounting the FILE into the
%% container pins the inode, so the path can never resolve to the new file and
%% no guard here can help. The directory is what must be mounted. See
%% deploy/docker-compose.yml.
follow(#st{path = Path} = St) ->
    followed(St, file:read_file_info(Path)).

%% No readable log at the path (yet). Keep what we hold and retry next poll.
followed(St, {error, _}) ->
    St;
%% First open. Start at the end: we care about live attacks, not history.
%% This clause must precede the inode clause, which an unset inode also matches.
followed(#st{fd = undefined} = St, {ok, Info}) ->
    open_at(St, Info, eof);
%% Renamed and recreated: a different file answers to the path now.
followed(#st{inode = Inode} = St, {ok, #file_info{inode = Fresh} = Info})
  when Fresh =/= Inode ->
    open_at(release(St), Info, 0);
%% Truncated in place: the file we hold is shorter than where we are in it.
followed(#st{pos = Pos} = St, {ok, #file_info{size = Size} = Info})
  when Size < Pos ->
    open_at(release(St), Info, 0);
followed(St, {ok, _Info}) ->
    St.

release(#st{fd = Fd} = St) ->
    _ = close(Fd),
    St#st{fd = undefined, inode = undefined}.

%% Take up the file at the path. A replacement is read from byte 0: the lines
%% written between the rotation and this poll are live sightings, not history.
open_at(#st{path = Path} = St, #file_info{inode = Inode}, Start) ->
    started(St#st{inode = Inode}, file:open(Path, [read, binary, raw]), Start).

started(St, {ok, Fd}, eof) ->
    {ok, Eof} = file:position(Fd, eof),
    St#st{fd = Fd, pos = Eof};
started(St, {ok, Fd}, Pos) ->
    St#st{fd = Fd, pos = Pos};
started(St, {error, _}, _Start) ->
    St#st{fd = undefined, inode = undefined}.

close(undefined) -> ok;
close(Fd)        -> file:close(Fd).

drain(#st{fd = undefined} = St) ->
    St;
drain(#st{fd = Fd, pos = Pos} = St) ->
    case file:pread(Fd, Pos, 65536) of
        {ok, Data} ->
            %% pread only returns {ok,_} when it read something, so reaching
            %% here IS the liveness event health/0 watches for.
            St2 = lists:foldl(fun line/2, St, binary:split(Data, <<"\n">>, [global])),
            drain(St2#st{pos = Pos + byte_size(Data),
                         last_read_ms = erlang:system_time(millisecond)});
        eof ->
            St;
        {error, _} ->
            St
    end.

%% A failed-auth line names a source IP (and often a username). Count it; when an
%% IP crosses the threshold in the window, report it once (then cool down).
line(Line, St) ->
    case parse(Line) of
        {ok, Ip, User} -> record(Ip, User, St);
        skip           -> St
    end.

parse(Line) ->
    Failed = binary:match(Line, <<"Failed password">>) =/= nomatch
             orelse binary:match(Line, <<"Invalid user">>) =/= nomatch
             orelse binary:match(Line, <<"authentication failure">>) =/= nomatch,
    parse(Failed, Line).

parse(false, _Line) ->
    skip;
parse(true, Line) ->
    case re:run(Line, <<"from ([0-9A-Fa-f:.]+)(?= port |\\s*$)">>, [{capture, [1], binary}]) of
        {match, [Text]} -> address(inet:parse_strict_address(binary_to_list(Text)), Line);
        nomatch         -> skip
    end.

%% v4 or v6, validated by inet rather than by the regex, and reported in one
%% canonical spelling so the same attacker is one key wherever it was seen. A
%% v4 client on a dual-stack socket arrives as ::ffff:a.b.c.d and is that v4
%% address.
address({ok, {0, 0, 0, 0, 0, 16#ffff, Hi, Lo}}, Line) ->
    address({ok, {Hi bsr 8, Hi band 255, Lo bsr 8, Lo band 255}}, Line);
address({ok, Ip}, Line) ->
    {ok, list_to_binary(inet:ntoa(Ip)), user_of(Line)};
address({error, einval}, _Line) ->
    skip.

user_of(Line) ->
    %% "Invalid user admin from ..." | "Failed password for root from ..." |
    %% "... user=root". Case-insensitive; the name runs to the next space.
    case re:run(Line, <<"(?:invalid user |user=|password for )([A-Za-z0-9._-]{1,32})">>,
                [caseless, {capture, [1], binary}]) of
        {match, [U]} -> U;
        nomatch      -> <<>>
    end.

record(Ip, User, St) ->
    Now = erlang:system_time(millisecond),
    Fresh = [T || T <- maps:get(Ip, St#st.hits, []), Now - T < ?WINDOW_MS],
    Hits = [Now | Fresh],
    Users = add_user(Ip, User, St#st.users),
    St2 = St#st{hits = maps:put(Ip, Hits, St#st.hits), users = Users},
    maybe_report(Ip, length(Hits), Now, St2).

add_user(_Ip, <<>>, Users) -> Users;
add_user(Ip, User, Users) ->
    Existing = maps:get(Ip, Users, []),
    case lists:member(User, Existing) of
        true  -> Users;
        false -> maps:put(Ip, lists:sublist([User | Existing], 20), Users)
    end.

maybe_report(Ip, Count, Now, St) when Count >= ?THRESHOLD ->
    Last = maps:get(Ip, St#st.reported, 0),
    report_if(Now - Last >= ?REPORT_COOLDOWN_MS, Ip, Count, Now, St);
maybe_report(_Ip, _Count, _Now, St) ->
    St.

report_if(false, _Ip, _Count, _Now, St) ->
    St;
report_if(true, Ip, Count, Now, St) ->
    Users = maps:get(Ip, St#st.users, []),
    logger:info("[warden] attacker sighted: ~s (~b attempts/~bs) users=~p",
                [Ip, Count, ?WINDOW_MS div 1000, Users]),
    ok = mcl_warden_facts:report_attacker_sighted(#{source_ip => Ip,
                                                    service => <<"ssh">>,
                                                    attempts => Count,
                                                    window_s => ?WINDOW_MS div 1000,
                                                    usernames => Users}),
    St#st{reported = maps:put(Ip, Now, St#st.reported)}.
