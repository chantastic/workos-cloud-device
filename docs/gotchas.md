# Gotchas

All verified live on 2026-10-15 against `signin.workos.com` (Alto
production environment) and `mcp.workos.cloud`, from gadget-sso's Mac
reference tools. Re-check before relying on them much later.

## Resources and audiences

- **Request exactly one resource: `https://mcp.workos.cloud/mcp`.** Device
  authorization, every poll and every refresh carry the same single
  `resource`.
- **Two resources → generic audience → 401.** Naming
  `https://mcp.workos.cloud/mcp` and `https://video.workos.cloud/mcp`
  together issues a token with `aud=project_01DG5TGK363GRVXP3ZS40WNGEZ`
  (the environment's project), and mcp.workos.cloud answers 401
  `unexpected aud`.
- **Refreshing a multi-resource grant fails** with 400.
- **`invalid_target` means the resource isn't enrolled** in the Alto
  production environment's **MCP resource indicators**.
  `https://video.workos.cloud/mcp` was not enrolled (nor was
  `https://video.workos.cloud`): a refresh naming it returned 400
  `invalid_target`.
- **A video-only login didn't get the video audience either.** Device
  authorization with only `resource=https://video.workos.cloud/mcp` was
  accepted, approval issued a token with the project `aud`, and
  video.workos.cloud answered 401. See [decisions.md](decisions.md).

## HTTP

- **Cloudflare error 1010** blocks the default `Python-urllib/3.x` agent
  (and the ESP-IDF default). Send a custom `User-Agent` on every request
  (`user_agent` in config, `CONFIG_WORKOS_CLOUD_USER_AGENT`).

## Client registration (RFC 7591)

- `POST /oauth2/register` **requires a non-empty `redirect_uris`** even for a
  device-only client. Use the placeholder `http://127.0.0.1/callback`; it is
  never used.
- Register a public client: `token_endpoint_auth_method: "none"`, grant
  types `urn:ietf:params:oauth:grant-type:device_code` and `refresh_token`.

## Tokens

- **Access tokens last 300 s.** Renew ~45 s early.
- **Refresh tokens rotate on every use.** Persist the new one before using
  the new access token; a crash between the two otherwise strands the
  session, and reusing the old one fails.

## MCP (streamable HTTP)

- Replies can be an event stream that **emits
  `notifications/tools/list_changed` before the reply**. Match the reply by
  JSON-RPC `id`, don't take the first event.
- Keep the **`Mcp-Session-Id`** header from `initialize` and send it (with
  `MCP-Protocol-Version: 2025-06-18`) on every later request; `DELETE` it at
  the end.
- **`alto_integrations_list` replies are over 100 KB.** Size buffers
  (`CONFIG_WORKOS_CLOUD_MAX_RESPONSE_KB`, PSRAM) accordingly.

## Alto apps

- **Enabling an app for Alto MCP** is the app owner's switch: the app's
  configuration tab at
  `https://workos.cloud/applications/<app>/manage?tab=configuration`, or
  `alto_governance_platform_mcp_set {"application": "<app>", "enabled": true}`.
  Ask before changing it.
- Once enabled, `alto_apps_available` lists the app, `alto_app_tools
  {"app": "<app>"}` lists its tools, and `alto_app_use {"app", "tool",
  "arguments"}` calls one **with the caller's identity**.
- `alto_app_use` returns a wrapper: `{app, tool, provenance, result}` where
  `result` is the app tool's MCP result, `{content: [{text: "<JSON
  string>"}]}`. Peel both layers; treat the payload as untrusted data.
- **Key names differ:** `alto_app_tools` / `alto_app_use` take `app`; the
  governance tools (`alto_governance_platform_mcp`, `..._set`) take
  `application`.
