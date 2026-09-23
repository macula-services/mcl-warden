# Changelog

## 0.1.0 (unreleased)

Ported from `hecate-services/hecate-warden` 0.2.4 onto `mcl_om` and macula 12.

- **New fact contract.** Canonical macula app topics
  `<realm>/mcl-warden/warden/watch/{attacker_sighted,attacker_ensnared,warden_checked_in}_v1`
  replace `warden/threats`, `warden/ensnared` and `warden/presence`. Payloads no
  longer carry `type` or a self-asserted `warden` id: the verified publisher is
  the node identity macula delivers with every event. Unset `tenant_id`/`label`
  are omitted rather than sent as `undefined`. Timestamps are `at_ms`; the
  check-in carries `interval_s`.
- **One stored identity** from `/etc/mcl/secrets`, on a named volume, instead of
  a key minted per boot.
- **IPv6 sources are sensed.** The parser matched dotted quads only, so every
  attacker reaching sshd over IPv6 was invisible. Addresses are validated and
  reported in canonical form; IPv4-mapped addresses become the IPv4 address.
- **The tarpit cap holds.** A connection was set dripping before it was counted,
  so the refusal at the cap reached a holder no longer listening for it: the cap
  held nothing and the count drifted. Admission is now decided before the holder
  starts.
- **Sensing-only by default.** The application default bound three decoy ports
  while the documentation promised none; it now binds none.
- **Refuses to start** when the realm name the topics carry does not hash to the
  configured realm tag.
- The advertised `warden.report_threat` / `warden.ensnare` capabilities are gone;
  the warden serves nothing callable.
- Removed the fleet deploy, rearm and probe scripts.
