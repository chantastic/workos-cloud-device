// workos_cloud: sign a keyboardless ESP32 in with a WorkOS SSO identity
// (RFC 8628 device grant at signin.workos.com) and call read-only tools on
// the Alto MCP server at mcp.workos.cloud over that session.
//
// Typical use, all from one task (the calls block on HTTPS):
//
//     wc_config_t cfg;
//     wc_config_default(&cfg);              // Kconfig values
//     cfg.client_id = "client_...";         // public client from DCR
//     wc_init(&cfg);
//     if (!wc_has_saved_session() || wc_refresh() != 200) {
//         wc_device_code_t code;
//         wc_device_start(&code, &status);  // show code.user_code + QR of code.verification_uri
//         while (!wc_device_expired()) {
//             if (wc_device_due()) { wc_device_poll(NULL, NULL, &report); if (!report.more) break; }
//             vTaskDelay(...);
//         }
//     }
//     const char *bearer = wc_bearer(&status);
//     wc_mcp_t m;
//     wc_mcp_open(&m, bearer);
//     cJSON *r = wc_mcp_call_tool(&m, bearer, "alto_whoami");
//
// Secrets: the access token lives in RAM only; the refresh token is kept in
// NVS (cfg.nvs_namespace / cfg.nvs_refresh_key) and rotated on every use.
// This component never logs either. No client secret or API key is used.
//
// One resource: every token request names exactly cfg.resource. Two
// resources make the token's aud the project, which mcp.workos.cloud
// rejects. Reach other Alto apps through wc_mcp_app_use, not a second
// resource.
//
// Calls are refused locally unless cfg.allowlist allows them; tool output
// is untrusted data for display only.
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cJSON.h"
#include "esp_err.h"
#include "workos_cloud_core.h"

#ifdef __cplusplus
extern "C" {
#endif

// ---- configuration ---------------------------------------------------------

typedef enum {
    WC_EVENT_TOKENS,    // a token response was accepted (sign-in or refresh)
    WC_EVENT_REFRESH,   // a refresh finished; status holds its HTTP status
} wc_event_kind_t;

typedef struct {
    wc_event_kind_t kind;
    int status;           // WC_EVENT_REFRESH: see wc_refresh()
    int lifetime_s;       // WC_EVENT_TOKENS: access-token lifetime (0: unknown)
    int renew_in_s;       // WC_EVENT_TOKENS: renewed from this many seconds on
    int64_t expires_us;   // esp_timer µs when the token expires (0: unknown)
    int64_t renews_us;    // esp_timer µs when wc_bearer() will renew it
    bool rotated;         // a new refresh token was saved
} wc_event_t;

// Strings are borrowed: they must outlive the component (literals are fine).
typedef struct {
    const char *auth_server;       // "https://signin.workos.com"
    const char *resource;          // the one RFC 8707 resource, also the MCP URL
    const char *client_id;         // public client (tools/wcd.py register); required
    const char *scope;             // "openid profile email offline_access"
    const char *user_agent;        // custom: Cloudflare 1010 blocks library defaults
    const char *client_name;       // MCP clientInfo.name
    const char *client_version;    // MCP clientInfo.version
    const char *nvs_namespace;     // refresh token location (<= 15 chars each)
    const char *nvs_refresh_key;
    wc_allowlist_t allowlist;      // what the device may call on its own
    size_t max_response;           // MCP reply cap in bytes (alto_integrations_list is 100 KB+)
    int timeout_ms;                // per HTTPS request
    void (*on_event)(const wc_event_t *event, void *ctx);   // optional; runs on the calling task
    void *ctx;
} wc_config_t;

// Fill cfg from Kconfig (menuconfig: "WorkOS Cloud device client").
void wc_config_default(wc_config_t *cfg);
// Validate and keep cfg; allocate the token buffer (PSRAM when present).
// ESP_ERR_INVALID_ARG when client_id is empty or resource isn't one https URL.
esp_err_t wc_init(const wc_config_t *cfg);
const wc_config_t *wc_config(void);

// ---- session ---------------------------------------------------------------

bool wc_has_saved_session(void);
// Renew from the saved refresh token, saving the rotated one before the new
// access token is used. Returns the HTTP status: 200 a new session, 401
// nothing saved, 0 no response, -1 an unusable response or NVS failure.
int wc_refresh(void);
// The server refused the session (4xx other than 429): it won't come back.
bool wc_status_rejected(int status);
// Forget the session: erase the saved refresh token, wipe the access token.
void wc_forget(void);
// A current access token, refreshed when near expiry; NULL when none. A
// rejected refresh forgets the session. *status (optional) gets the
// refresh status, or 200 when none was needed. Valid until the next call.
const char *wc_bearer(int *status);
// A server answered 401: the next wc_bearer() refreshes first.
void wc_expire_access(void);

// ---- device grant (RFC 8628) -------------------------------------------------

typedef struct {
    char user_code[24];
    char verification_uri[320];   // verification_uri_complete when offered; encode it as the QR
    uint32_t interval_s;
    int expires_in_s;
} wc_device_code_t;

// Ask for a device code. false: *status is the HTTP status (0: no response).
bool wc_device_start(wc_device_code_t *out, int *status);
bool wc_device_due(void);
bool wc_device_expired(void);

typedef struct {
    int status;            // HTTP status of the token request (0: none)
    wc_grant_t grant;
    bool absorbed;         // WC_GRANT_SUCCESS and the session was accepted and saved
    bool more;             // keep polling
    uint32_t interval_s;   // after slow_down
    uint32_t polls;
} wc_poll_report_t;

// One token request. When keep is given and returns false once the reply
// is in (the user canceled meanwhile), the tokens are discarded.
void wc_device_poll(bool (*keep)(void *ctx), void *ctx, wc_poll_report_t *out);
void wc_device_cancel(void);

// GET {auth_server}/oauth2/userinfo. Caller deletes.
cJSON *wc_userinfo(const char *bearer, int *status);

// ---- MCP (streamable HTTP) on cfg.resource -----------------------------------

typedef struct {
    char session[160];   // Mcp-Session-Id, when the server assigns one
    int status;          // HTTP status of the last request (0: no response)
    int next_id;
    char error[96];      // last failure, plain words
    char server[48];     // serverInfo.name from initialize
} wc_mcp_t;

// initialize + notifications/initialized. false: see m->status / m->error.
bool wc_mcp_open(wc_mcp_t *m, const char *bearer);
// tools/list; its "tools" array holds the tools. Caller deletes.
cJSON *wc_mcp_list_tools(wc_mcp_t *m, const char *bearer);
// tools/call with {} for a tool in allowlist.direct_tools; else refused.
cJSON *wc_mcp_call_tool(wc_mcp_t *m, const char *bearer, const char *name);
// tools/call with {} for a tools/list entry that wc_mcp_tool_safe allows.
cJSON *wc_mcp_call_listed(wc_mcp_t *m, const char *bearer, const cJSON *tool);
// alto_app_use {app, tool, arguments} for an allowlist.app_tools pair;
// arguments are consumed. Returns the tool result; peel it with
// wc_app_use_unwrap. Anything else is refused before it is sent.
cJSON *wc_mcp_app_use(wc_mcp_t *m, const char *bearer, const char *app, const char *tool, cJSON *arguments);
// End the server session (DELETE) when there is one.
void wc_mcp_close(wc_mcp_t *m, const char *bearer);
// wc_tool_json_safe with the configured allowlist.
bool wc_mcp_tool_safe(const cJSON *tool);

#ifdef __cplusplus
}
#endif
