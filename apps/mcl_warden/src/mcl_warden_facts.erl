%%% @doc The warden's public contract: what it tells the threat commons.
%%%
%%% Three integration facts, and nothing else leaves the box:
%%%
%%%   attacker_sighted_v1   a source IP crossed the failed-auth threshold on
%%%                         this box's real sshd
%%%   attacker_ensnared_v1  the tarpit held a connection until it gave up
%%%   warden_checked_in_v1  heartbeat, so a consumer builds its roster live
%%%
%%% Topics are canonical macula app facts owned by org `mcl-warden', app
%%% `warden', domain `watch', for example
%%% `io.macula/mcl-warden/warden/watch/attacker_sighted_v1'. The org segment is
%%% the schema owner and is fixed here, not deploy config: a third party running
%%% the warden publishes the same contract, and names itself in `tenant_id'.
%%%
%%% WHO SENT A FACT IS NOT IN THE PAYLOAD. macula 12 delivers every event with
%%% the publisher its link verified, which is the warden's stored node identity.
%%% A consumer attributes by that. `tenant_id' (which organisation) and `label'
%%% (which box) are self-asserted display attribution, absent when unset.
%%%
%%% Payload values are binaries, integers and lists of binaries only. Flags are
%%% 1/0. Times are milliseconds since the epoch, in `at_ms'.
-module(mcl_warden_facts).

-export([report_attacker_sighted/1, report_attacker_ensnared/2, check_in/0,
         check_realm_name/0]).
-export([topic/2, attacker_sighted/2, attacker_ensnared/3, warden_checked_in/1,
         context/0, check_realm_name/2, check_in_interval_ms/0]).

-define(ORG, <<"mcl-warden">>).
-define(APP, <<"warden">>).
-define(DOMAIN, <<"watch">>).
-define(VERSION, 1).
-define(CHECK_IN_INTERVAL_S, 60).

-type fact() :: attacker_sighted | attacker_ensnared | warden_checked_in.
-type context() :: #{at_ms := integer(), tarpit := 0 | 1,
                     tenant_id => binary(), label => binary(),
                     lat_e6 => integer(), lng_e6 => integer()}.

-export_type([fact/0, context/0]).

%%------------------------------------------------------------------------------
%% Publishing
%%------------------------------------------------------------------------------

%% @doc A source IP crossed the threshold on the real sshd.
-spec report_attacker_sighted(map()) -> ok.
report_attacker_sighted(Sighting) ->
    publish(attacker_sighted, attacker_sighted(Sighting, context())).

%% @doc The tarpit held `Ip' for `HeldMs' before it gave up.
-spec report_attacker_ensnared(binary(), non_neg_integer()) -> ok.
report_attacker_ensnared(Ip, HeldMs) ->
    publish(attacker_ensnared, attacker_ensnared(Ip, HeldMs, context())).

%% @doc The heartbeat.
-spec check_in() -> ok.
check_in() ->
    publish(warden_checked_in, warden_checked_in(context())).

%% @doc Refuse to start when the configured realm name is not the realm the
%% pool publishes in. Called from the service's start/1.
-spec check_realm_name() -> ok.
check_realm_name() ->
    check_configured(realm_name(), mcl_om:realm()).

check_configured(Name, {ok, Tag}) -> check_realm_name(Name, Tag);
check_configured(Name, Other)     -> error({mcl_warden_realm_unset, Name, Other}).

%% The mesh being dark is not the warden's problem to solve: it keeps sensing
%% and the fact is dropped. A refused publish is logged by mcl_om (async_log),
%% because a warden whose facts are refused looks exactly like a warden with
%% nothing to report.
publish(Fact, Payload) ->
    _ = mcl_om_pubsub:publish(topic(realm_name(), Fact), Payload,
                              #{mode => async_log}),
    ok.

%%------------------------------------------------------------------------------
%% The contract, pure
%%------------------------------------------------------------------------------

-spec topic(binary(), fact()) -> binary().
topic(RealmName, Fact) ->
    macula_topic:app_fact(RealmName, ?ORG, ?APP, ?DOMAIN,
                          atom_to_binary(Fact, utf8), ?VERSION).

-spec check_realm_name(binary(), binary()) -> ok.
check_realm_name(Name, Tag) ->
    matched(crypto:hash(sha256, Name) =:= Tag, Name, Tag).

matched(true, _Name, _Tag) -> ok;
matched(false, Name, Tag)  -> error({mcl_warden_realm_name_mismatch, Name, Tag}).

-spec attacker_sighted(map(), context()) -> map().
attacker_sighted(#{source_ip := Ip, service := Service, attempts := Attempts,
                   window_s := WindowS, usernames := Usernames}, Ctx) ->
    attributed(#{source_ip => Ip, service => Service, attempts => Attempts,
                 window_s => WindowS, usernames => Usernames}, Ctx).

-spec attacker_ensnared(binary(), non_neg_integer(), context()) -> map().
attacker_ensnared(Ip, HeldMs, Ctx) ->
    attributed(#{source_ip => Ip, held_ms => HeldMs}, Ctx).

-spec warden_checked_in(context()) -> map().
warden_checked_in(#{tarpit := Tarpit} = Ctx) ->
    Base = #{tarpit => Tarpit, interval_s => ?CHECK_IN_INTERVAL_S},
    attributed(maps:merge(Base, maps:with([lat_e6, lng_e6], Ctx)), Ctx).

attributed(Fact, #{at_ms := At} = Ctx) ->
    maps:merge(Fact#{at_ms => At}, maps:with([tenant_id, label], Ctx)).

-spec check_in_interval_ms() -> pos_integer().
check_in_interval_ms() -> ?CHECK_IN_INTERVAL_S * 1000.

%%------------------------------------------------------------------------------
%% The context every fact is stamped with, from app env
%%------------------------------------------------------------------------------

-spec context() -> context().
context() ->
    Present = [{K, V} || {K, V} <- [{tenant_id, text(env(tenant_id))},
                                    {label, text(env(label))},
                                    {lat_e6, micro_degrees(env(lat_e6))},
                                    {lng_e6, micro_degrees(env(lng_e6))}],
                         V =/= undefined],
    maps:from_list([{at_ms, erlang:system_time(millisecond)},
                    {tarpit, tarpit(env(tarpit_ports))} | Present]).

env(Key) -> application:get_env(mcl_warden, Key, undefined).

realm_name() -> text_or_unset(text(env(realm_name))).

text_or_unset(undefined) -> error({mcl_warden_realm_name_unset, realm_name});
text_or_unset(Name)      -> Name.

text(undefined) -> undefined;
text("")        -> undefined;
text(<<>>)      -> undefined;
text(S) when is_list(S)   -> unicode:characters_to_binary(S);
text(B) when is_binary(B) -> B.

%% Micro-degrees, an integer: the wire has no floats worth trusting.
micro_degrees(undefined) -> undefined;
micro_degrees(S) when is_list(S) -> whole_integer(string:to_integer(S));
micro_degrees(I) when is_integer(I) -> I.

whole_integer({I, ""}) when is_integer(I) -> I;
whole_integer(_Malformed)                 -> undefined.

tarpit([_ | _]) -> 1;
tarpit(_)       -> 0.
