%%% @doc One ensnared connection, held open forever (or until they give up).
%%%
%%% endlessh's whole trick, and it is beautiful in its cruelty: an SSH client,
%%% before it sends anything, waits for the server's identification banner
%%% ("SSH-2.0-..."). The RFC says the server may send any number of lines BEFORE
%%% that banner. So we send banner lines — slowly, one every few seconds, forever
%%% — and never send the line that would let the handshake begin. The client
%%% waits. And waits. A patient scanner will hold for hours.
%%%
%%% We send RANDOM junk lines, not a real banner, for two reasons: it is
%%% harmless (a real client discards pre-banner lines), and it denies the
%%% attacker any fingerprint of what they are stuck on. We never read their
%%% input. There is nothing here to exploit.
-module(tarpit_connection).

-export([start/2, go/1, drop/1]).
-export([junk_line/0]).  %% exported for tests

%% Each line stays under 255 bytes: the SSH RFC caps a pre-banner line there, so
%% a compliant client keeps reading instead of hanging up.
-define(LINE_MAX, 32).

%% One junk line every `DripMs': slow enough to hold for hours, fast enough
%% that a very patient client keeps believing something is coming.
-spec start(gen_tcp:socket(), pos_integer()) -> {ok, pid()}.
start(Conn, DripMs) ->
    Pid = spawn(fun() -> wait(Conn, DripMs) end),
    {ok, Pid}.

%% The listener calls this AFTER it has handed us ownership of the socket, so we
%% don't touch it before controlling_process/2 has run.
-spec go(pid()) -> ok.
go(Pid) ->
    Pid ! go,
    ok.

%% @doc The listener is at its cap; let this one go instead of holding it.
-spec drop(pid()) -> ok.
drop(Pid) ->
    Pid ! drop,
    ok.

wait(Conn, DripMs) ->
    receive
        go   -> Peer = peer_ip(Conn),
                drip(Conn, Peer, DripMs, erlang:monotonic_time(millisecond));
        drop -> catch gen_tcp:close(Conn)
    after 5000 ->
        catch gen_tcp:close(Conn)
    end.

drip(Conn, Peer, DripMs, Start) ->
    case gen_tcp:send(Conn, junk_line()) of
        ok ->
            timer:sleep(DripMs),
            drip(Conn, Peer, DripMs, Start);
        {error, _Reason} ->
            %% They gave up (or the socket died). Report how long we held them.
            HeldMs = erlang:monotonic_time(millisecond) - Start,
            catch gen_tcp:close(Conn),
            gen_server:cast(tarpit_listener, {released, self(), Peer, HeldMs})
    end.

%% A random pre-banner line: printable junk, CRLF-terminated, never starting
%% with "SSH-" (that would end the game).
junk_line() ->
    N = 1 + rand:uniform(?LINE_MAX),
    Junk = << <<(printable())>> || _ <- lists:seq(1, N) >>,
    <<Junk/binary, "\r\n">>.

printable() ->
    32 + rand:uniform(94).   %% ' ' .. '~'

peer_ip(Conn) ->
    case inet:peername(Conn) of
        {ok, {Ip, _Port}} -> list_to_binary(inet:ntoa(Ip));
        _                 -> <<"unknown">>
    end.
