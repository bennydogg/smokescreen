# homenet-smokescreen

Stripe's [Smokescreen](../../README.md) with two additions for a home LAN,
kept in this fork as its own command so upstream can be merged underneath it:

1. **Role by client IP.** Upstream identifies the calling service by its
   client TLS certificate. Here every proxy client is a VM with a DHCP
   reservation, so `RoleFromRequest` looks the peer IP up in a roles file.
   An unknown client is still a role (`unknown_role`, default
   `unclassified`) and the ACL decides what it may do — nothing is ever
   "role cannot be determined".
2. **Time-boxed grants.** A `grants.yaml` next to the ACL holds
   `role + host glob + expiry` entries that are consulted *before* the ACL
   and re-read whenever the file changes. A grant takes effect within a few
   seconds of being written and expires on its own — no restart, and the
   versioned ACL never drifts.

Everything else is upstream Smokescreen: the ACL format and its
enforce / report / open verdicts, the private-range resolver guard, the
JSON decision log, Prometheus metrics, the CLI flags.

## Files

| Env var (container default) | What |
|---|---|
| `SMOKESCREEN_ROLES_FILE` (`/etc/smokescreen/roles.yaml`) | `roles: [{name, members: [ip or cidr, …]}]`, `unknown_role: name` |
| `SMOKESCREEN_ACL_FILE` (`/etc/smokescreen/acl.yaml`) | upstream ACL v1; used by `check` / `decide` (the daemon takes `--egress-acl-file`) |
| `SMOKESCREEN_GRANTS_FILE` (`/etc/smokescreen/grants.yaml`) | `grants: [{role, host, expires: RFC3339, reason, by}]`; absent = none |

Every role in the roles file must have a service in the ACL — `check`
fails otherwise, so a typo cannot silently route a VM to the default rule.

## Commands

```sh
smokescreen check                    # validate acl + roles + grants, exit 0/1
smokescreen decide <role> <host>     # ALLOW / ALLOW (report) / DENY, with reason; exit 2 on deny
smokescreen --listen-port 4750 --egress-acl-file /etc/smokescreen/acl.yaml …   # the proxy
```

The daemon refuses to start without `--egress-acl-file`: this proxy is
allowlist-or-deny by design, never accidentally open. `/healthcheck`
answers `200 ok` on the proxy port.

## Decision log

One JSON line per request, `msg: CANONICAL-PROXY-DECISION`, with `role`,
`requested_host`, `inbound_remote_addr`, `allow`, `enforce_would_deny`,
`decision_reason`, `proxy_type` (`http` or `connect`). A report-mode miss is
`allow: true` + `enforce_would_deny: true`; a denial is `allow: false` and
the client sees `407` with an `X-Smokescreen-Error` header (upstream's
convention). A temporary grant logs `decision_reason: temporary grant until …`.

## Build

```sh
GOFLAGS=-mod=vendor go build ./cmd/homenet-smokescreen
GOFLAGS=-mod=vendor go test ./cmd/homenet-smokescreen/...
docker build -t ghcr.io/bennydogg/smokescreen:homenet .      # the repo Dockerfile builds this command
```

`.github/workflows/homenet-image.yml` publishes `ghcr.io/bennydogg/smokescreen:homenet`
(and an immutable `homenet-<sha>`) on every push to master. The deployment
that consumes it — policy, compose, deploy and grant tooling — is
`network/services/smokescreen/` in the homenet repo.

## Keeping the fork current

`git fetch upstream && git merge upstream/master`. This command only uses
`cmd.NewConfiguration`, `Config.RoleFromRequest`, `Config.EgressACL`
(`acl.Decider`), `Config.Healthcheck` and `smokescreen.StartWithConfig`; if
an upstream change touches those, `go vet ./cmd/homenet-smokescreen/...`
and the unit tests say so before the image does.
