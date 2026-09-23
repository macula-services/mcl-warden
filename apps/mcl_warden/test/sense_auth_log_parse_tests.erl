%%% @doc Reading one auth-log line: the source address and the username tried.
-module(sense_auth_log_parse_tests).

-include_lib("eunit/include/eunit.hrl").

failed_password_test() ->
    L = <<"Jul 13 12:00:01 host sshd[1]: Failed password for root from "
          "203.0.113.7 port 4021 ssh2">>,
    ?assertEqual({ok, <<"203.0.113.7">>, <<"root">>}, sense_auth_log:parse(L)).

invalid_user_test() ->
    L = <<"Jul 13 12:00:02 host sshd[1]: Invalid user admin from 198.51.100.9">>,
    ?assertEqual({ok, <<"198.51.100.9">>, <<"admin">>}, sense_auth_log:parse(L)).

pam_authentication_failure_test() ->
    L = <<"Jul 13 12:00:04 host sshd[1]: pam_unix(sshd:auth): authentication "
          "failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.8 user=oracle">>,
    %% No "from": the address is in rhost=, which this sensor does not read.
    %% The same attempt also writes a "Failed password ... from" line, which it
    %% does, so the attempt is counted exactly once.
    ?assertEqual(skip, sense_auth_log:parse(L)).

noise_is_skipped_test() ->
    ?assertEqual(skip, sense_auth_log:parse(
        <<"Jul 13 12:00:03 host systemd[1]: Started Session 5.">>)).

%% The public boxes are reachable over IPv6, and sshd logs a v6 source as it
%% is. A sensor that only matches dotted quads is blind to every one of them.
failed_password_from_ipv6_test() ->
    L = <<"Jul 13 12:00:05 host sshd[1]: Failed password for root from "
          "2001:db8::1:7 port 51122 ssh2">>,
    ?assertEqual({ok, <<"2001:db8::1:7">>, <<"root">>}, sense_auth_log:parse(L)).

invalid_user_from_ipv6_test() ->
    L = <<"Jul 13 12:00:06 host sshd[1]: Invalid user pi from 2001:db8:a:b::9 port 4022">>,
    ?assertEqual({ok, <<"2001:db8:a:b::9">>, <<"pi">>}, sense_auth_log:parse(L)).

%% One attacker, one key: a v6 address spelled with capitals or leading zeros
%% is the same address and must correlate with its canonical spelling.
ipv6_is_reported_in_canonical_form_test() ->
    L = <<"Jul 13 12:00:07 host sshd[1]: Failed password for root from "
          "2001:0DB8:0000::0001 port 1 ssh2">>,
    ?assertEqual({ok, <<"2001:db8::1">>, <<"root">>}, sense_auth_log:parse(L)).

%% A v4 client on a dual-stack socket is logged as ::ffff:a.b.c.d. It is the
%% v4 attacker, and must correlate with the same address seen over v4.
ipv4_mapped_ipv6_is_reported_as_ipv4_test() ->
    L = <<"Jul 13 12:00:08 host sshd[1]: Failed password for root from "
          "::ffff:203.0.113.7 port 1 ssh2">>,
    ?assertEqual({ok, <<"203.0.113.7">>, <<"root">>}, sense_auth_log:parse(L)).

%% Something shaped like an address that is not one is not a sighting.
not_an_address_is_skipped_test() ->
    L = <<"Jul 13 12:00:09 host sshd[1]: Failed password for root from "
          "999.1.1.1 port 1 ssh2">>,
    ?assertEqual(skip, sense_auth_log:parse(L)).

%% The attacker picks the username. One that is itself hex, or the word
%% "from", must not be mistaken for the address that follows it.
a_username_that_looks_like_an_address_is_not_one_test() ->
    L = <<"Jul 13 12:00:10 host sshd[1]: Invalid user from from 203.0.113.9 port 1">>,
    ?assertEqual({ok, <<"203.0.113.9">>, <<"from">>}, sense_auth_log:parse(L)),
    L2 = <<"Jul 13 12:00:11 host sshd[1]: Invalid user face from 203.0.113.9 port 1">>,
    ?assertEqual({ok, <<"203.0.113.9">>, <<"face">>}, sense_auth_log:parse(L2)).
