# Flow

A device with a screen (or a serial console) and no keyboard signs in with
the user's SSO identity, then calls Alto MCP tools as that user.

```mermaid
sequenceDiagram
    autonumber
    participant D as Device
    participant AS as signin.workos.com
    participant P as Phone (browser)
    participant IdP as Okta (company SSO)
    participant MCP as mcp.workos.cloud (Alto)
    participant App as Alto app (e.g. video)

    Note over D,AS: Once per client: POST /oauth2/register (DCR, public client)
    D->>AS: POST /oauth2/device_authorization<br/>client_id, scope, resource=https://mcp.workos.cloud/mcp
    AS-->>D: device_code, user_code, verification_uri_complete, interval, expires_in
    D->>D: show user_code + QR(verification_uri_complete)
    P->>AS: open the QR URL, confirm the code
    AS->>IdP: SSO redirect
    IdP-->>AS: assertion for the user
    P->>AS: approve the device
    loop every interval (slow_down adds 5 s)
        D->>AS: POST /oauth2/token<br/>grant_type=device_code, device_code, client_id, resource
        AS-->>D: authorization_pending ... then access_token (300 s) + refresh_token
    end
    D->>D: save refresh_token (NVS / .local), keep access_token in RAM
    D->>AS: GET /oauth2/userinfo (Bearer)
    AS-->>D: sub, name, email
    D->>MCP: POST /mcp initialize (Bearer)
    MCP-->>D: serverInfo + Mcp-Session-Id
    D->>MCP: notifications/initialized, tools/list
    D->>MCP: tools/call alto_whoami {}
    MCP-->>D: {user, organization}
    D->>MCP: tools/call alto_app_use {app:"video", tool:"list_videos", arguments:{limit:1}}
    MCP->>App: list_videos as the caller
    App-->>MCP: MCP result {content:[{text:"<JSON>"}]}
    MCP-->>D: {app, tool, provenance, result} (untrusted: display only)
    Note over D,AS: Before expiry: POST /oauth2/token grant_type=refresh_token,<br/>same single resource; save the rotated refresh token first
    D->>MCP: DELETE /mcp (Mcp-Session-Id)
```

## 0. Register a client (once)

RFC 7591 dynamic client registration, done from a computer
(`tools/wcd.py register`), not the device:

```
POST https://signin.workos.com/oauth2/register
{"client_name": "...", "redirect_uris": ["http://127.0.0.1/callback"],
 "grant_types": ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
 "token_endpoint_auth_method": "none", "scope": "openid profile email offline_access"}
```

The answer's `client_id` is public. It goes in the config
(`CONFIG_WORKOS_CLOUD_CLIENT_ID`, `config/workos-cloud.json`). There is no
secret.

## 1. Device authorization (RFC 8628 §3.1)

Form-encoded. Every token-endpoint request in this flow carries the same
single resource (RFC 8707):

```
POST /oauth2/device_authorization
client_id=…&scope=openid%20profile%20email%20offline_access&resource=https%3A%2F%2Fmcp.workos.cloud%2Fmcp
```

The device shows `user_code` and encodes `verification_uri_complete` (else
`verification_uri`) as the QR. Only `https://` URIs are accepted.

## 2. Poll (RFC 8628 §3.4–3.5)

```
POST /oauth2/token
grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=…&client_id=…&resource=…
```

| Answer | Device |
| --- | --- |
| 200 with `access_token` | accept, stop |
| `authorization_pending` | wait `interval`, poll again |
| `slow_down` | interval += 5 s (cap 60 s), poll again |
| `access_denied` | stop: denied |
| `expired_token`, or local `expires_in` passed | stop: expired |
| no response, 5xx, 429 | transient: keep polling until expiry |
| anything else (e.g. `invalid_target`) | stop: failed |

These rules are `wc_grant_classify` / `wc_poll_*` in the core, host-tested.

## 3. Accept tokens

- `token_type` must be `Bearer` (or absent).
- Lifetime: `expires_in`, else the JWT's `exp - iat`, else 300 s. The token
  is renewed 45 s early (never sooner than 15 s). Live tokens last 300 s.
- A new `refresh_token` replaces the saved one **before** the access token is
  used: refresh tokens rotate on every use and the old one stops working.
- No `org_id` / `client_id` claims are required and nothing is verified
  locally; mcp.workos.cloud verifies `aud`, signature and expiry.

## 4. Refresh

```
POST /oauth2/token
grant_type=refresh_token&refresh_token=…&client_id=…&resource=https%3A%2F%2Fmcp.workos.cloud%2Fmcp
```

4xx (other than 429): the session is gone; forget it and sign in again.
No response / 5xx: keep the saved token and retry later. A 401 from a
resource server renews once (`wc_expire_access`) before giving up.

## 5. MCP on mcp.workos.cloud

Streamable HTTP, protocol `2025-06-18`. One POST per JSON-RPC message with
`Accept: application/json, text/event-stream`, `Authorization: Bearer`, and
a custom `User-Agent`.

1. `initialize` → keep the `Mcp-Session-Id` response header; send it and
   `MCP-Protocol-Version` on every later request.
2. `notifications/initialized` (202, no body).
3. `tools/list`, then `tools/call`.
4. `DELETE /mcp` with the session id when done.

A reply is either one JSON body or an event stream. The reply is the event
whose `id` matches the request; earlier events (such as
`notifications/tools/list_changed`) are skipped.

## 6. Other Alto apps through `alto_app_use`

```
tools/call alto_app_use {"app": "video", "tool": "list_videos", "arguments": {"limit": 1}}
```

Alto runs the app's tool with the caller's identity and wraps the answer:

```
result.content[0].text = '{"app":"video","tool":"list_videos","provenance":{…},
                           "result":{"content":[{"type":"text","text":"{\"videos\":[…]}"}]}}'
```

`wc_app_use_unwrap` (and `wcd.py`'s `unwrap_app_use`) peel each layer,
whether it arrives as `structuredContent` or JSON text, down to the app's
payload. An app-level `isError` becomes an error string. The payload is
untrusted data.

`alto_app_use` is annotated destructive and takes required arguments, so the
generic rule refuses it; only `app:tool` pairs in the allowlist are sent.
Discover an app's tools with `alto_app_tools {"app": "video"}`.
