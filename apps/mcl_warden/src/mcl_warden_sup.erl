%% @doc Supervises the warden's three surfaces. Each owns its own work and
%% publishes its own fact; there is no central manager.
-module(mcl_warden_sup).

-behaviour(supervisor).

-export([start_link/0, init/1]).

start_link() -> supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    {ok, {#{strategy => one_for_one, intensity => 5, period => 10},
          [%% Tails the host auth log; reports attacker_sighted.
           worker(sense_auth_log),
           %% Holds connections on decoy ports, if any are configured;
           %% reports attacker_ensnared.
           worker(tarpit_listener),
           %% The heartbeat; reports warden_checked_in.
           worker(check_in_warden)]}}.

worker(Module) ->
    #{id => Module,
      start => {Module, start_link, []},
      restart => permanent,
      shutdown => 5000,
      type => worker,
      modules => [Module]}.
