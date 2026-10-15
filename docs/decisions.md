# Decisions

## Reach apps through Alto (`alto_app_use`), not their own MCP resources

**Decision.** The device holds one token, for `https://mcp.workos.cloud/mcp`,
and reaches individual Alto apps (e.g. `video`) by calling `alto_app_use`
on that server. It does not request tokens for, or call, an app's own MCP
endpoint such as `https://video.workos.cloud/mcp`.

**Why.**

- *It works today.* Calling `video.workos.cloud/mcp` directly needs that URL
  enrolled in the Alto environment's MCP resource indicators. It was not
  (2026-10-15): refresh → `invalid_target`; video-only login → project `aud`
  → 401. Enrolment is an environment change owned by someone else.
- *One token can't serve two resources.* Asking for both resources at once
  yields the project audience, which mcp.workos.cloud rejects, and that
  grant can't be refreshed. Two separate sessions would double the device
  flow, the refresh-token storage, and the rotation bookkeeping on a device
  with a few KB of NVS per string.
- *Identity is preserved.* `alto_app_use` runs the app's tool as the
  caller, so the app sees the same user it would with a direct token.
- *Governance in one place.* The app owner decides whether the app is
  exposed (Alto platform MCP toggle), Alto records provenance, and the
  device's allowlist names `app:tool` pairs in one list.

**Costs.**

- An extra wrapper layer to peel (`{app, tool, provenance, result}`, with
  JSON in text twice), handled by `wc_app_use_unwrap`.
- `alto_app_use` is a generic dispatcher annotated destructive with
  required arguments, so the generic "read-only, no required arguments"
  rule can't vouch for it. The device therefore keeps an explicit
  `app:tool` allowlist and refuses everything else locally.
- The app must be enabled for Alto MCP by its owner first.
- One more hop of latency and Alto availability in the path.

**Revisit when** an app's own resource is enrolled and the device needs
something `alto_app_use` can't give (streaming, large payloads, lower
latency). Even then, request that resource in its *own* grant with its own
refresh token; never add it to the mcp.workos.cloud request.

## One resource in config, not a list

`resource` is a single string in `wc_config_t`, Kconfig and the CLI config,
and `wc_init` / `load_config` reject anything that looks like a list. A
list would invite the two-resource failure above.

## Allowlist defaults to named read-only tools

`direct_tools` names the Alto tools known to be read-only (`alto_whoami`,
`alto_apps_available`, `alto_integrations_list`); `app_tools` names
`video:list_videos` and `video:get_video_status`. A tool annotated
`readOnlyHint` with no required arguments is also callable. Guessing from a
name (`list_*`, `get*`) is available (`read_like_names`) but off by default:
a name is not a guarantee. gadget-sso turns it on to keep its Apps screen's
fallback for non-Alto servers.

## Core and adapter split

Everything that decides something (grant outcomes, poll timing, renew
timing, form bodies, reply matching, unwrapping, the allowlist) is in
`core/` and runs on a host under ASan/UBSan. `esp/` moves bytes. The CLI
reimplements the same rules in Python and has its own offline tests; when
one changes, change the other.

## Vendored cJSON for host tests

ESP-IDF 6 fetches cJSON from the component registry (`espressif/cjson`
1.7.19). The host tests compile the same version from `tests/vendor/cJSON`
so `make test` needs only a C compiler and no network.
