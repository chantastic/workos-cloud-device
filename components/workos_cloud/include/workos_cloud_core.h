// workos_cloud core: the hardware-free half of the workos.cloud device
// client. No HTTP, no NVS, no clocks: callers pass times and responses in.
// Everything here builds and is tested on a host (tests/).
//
//   - RFC 8628 device grant rules: classify a token response, poll schedule
//   - session timing: when to renew an access token
//   - application/x-www-form-urlencoded bodies, JWT payload decode
//   - MCP streamable HTTP: event-stream walking, JSON-RPC builders, reply
//     matching by id, tool results, the alto_app_use wrapper
//   - the allowlist: which tools a device may call on its own
//
// The JSON half uses cJSON (ESP-IDF: espressif/cjson; host: tests/vendor).
// Nothing here verifies a token: the servers that receive it do.
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

// ---- device grant (RFC 8628) ---------------------------------------------

typedef enum {
    WC_GRANT_SUCCESS = 0,   // tokens issued
    WC_GRANT_PENDING,       // authorization_pending: keep polling
    WC_GRANT_SLOW_DOWN,     // slow_down: keep polling, interval += 5 s
    WC_GRANT_DENIED,        // access_denied: stop
    WC_GRANT_EXPIRED,       // expired_token (or local deadline): stop
    WC_GRANT_NETWORK,       // no response, 5xx or 429: transient, keep polling
    WC_GRANT_FAILED,        // anything else: stop
} wc_grant_t;

// status: HTTP status, or 0 when the request never completed.
// error: the response's "error" string, or NULL.
// has_tokens: the response carried an access token.
wc_grant_t wc_grant_classify(int status, const char *error, bool has_tokens);
const char *wc_grant_name(wc_grant_t grant);

#define WC_POLL_DEFAULT_INTERVAL_S 5
#define WC_POLL_SLOW_DOWN_S 5
#define WC_POLL_MAX_INTERVAL_S 60

typedef struct {
    uint32_t interval_s;
    uint32_t deadline_ms;
    uint32_t next_ms;
    uint32_t polls;
} wc_poll_t;

// interval_s / expires_in_s come from the device authorization response
// (<= 0: 5 s / 5 minutes). Times are a wrapping millisecond clock.
void wc_poll_start(wc_poll_t *poll, uint32_t now_ms, int interval_s, int expires_in_s);
bool wc_poll_due(const wc_poll_t *poll, uint32_t now_ms);
bool wc_poll_expired(const wc_poll_t *poll, uint32_t now_ms);
// Schedule after a response. Returns true when polling should continue.
bool wc_poll_after(wc_poll_t *poll, uint32_t now_ms, wc_grant_t result);

// ---- session ---------------------------------------------------------------

// Seconds from now until an access token should be renewed. expires_in is
// the token response's lifetime; when absent (<= 0) the JWT's exp - iat is
// used, then 300 s. Renewal leads expiry by 45 s, never sooner than 15 s.
int wc_session_renew_in(int expires_in, double exp, double iat);

// Append key=value to an application/x-www-form-urlencoded body, percent-
// encoding everything outside RFC 3986's unreserved set. Returns false,
// leaving out unchanged, when the result would not fit.
bool wc_form_add(char *out, size_t size, const char *key, const char *value);

// Decode a JWT's payload segment (base64url, unpadded) into out as a
// NUL-terminated JSON string. Verifies nothing. Returns length or -1.
int wc_jwt_payload(const char *jwt, char *out, size_t out_size);

// A token-endpoint response, borrowed from the cJSON it was parsed from.
typedef struct {
    const char *access_token;    // never log
    const char *refresh_token;   // NULL when the server did not rotate it; never log
    int lifetime_s;              // expires_in, else exp - iat, else 0
    int renew_in_s;              // wc_session_renew_in()
} wc_tokens_t;

// Accept a token response: a non-empty access token shorter than
// access_max, token_type Bearer (or absent). No org_id / client_id claim
// is required. scratch (>= access_max bytes) decodes the JWT payload for
// exp / iat when expires_in is missing; it is wiped before returning.
bool wc_tokens_parse(const cJSON *response, size_t access_max, char *scratch, size_t scratch_size, wc_tokens_t *out);

// A device authorization response, borrowed from its cJSON.
typedef struct {
    const char *device_code;
    const char *user_code;
    const char *verification_uri;   // verification_uri_complete, else verification_uri; https only
    int interval_s;                 // 0 when absent
    int expires_in_s;               // 0 when absent
} wc_device_auth_t;

bool wc_device_auth_parse(const cJSON *response, wc_device_auth_t *out);

// ---- allowlist ---------------------------------------------------------------

// What a device may call on its own. Lists are whitespace- or comma-
// separated tokens matched exactly (Kconfig strings fit as they are).
typedef struct {
    // Tools called by name with empty arguments, e.g.
    // "alto_whoami alto_apps_available alto_integrations_list".
    const char *direct_tools;
    // alto_app_use pairs as app:tool, e.g. "video:list_videos video:get_video_status".
    const char *app_tools;
    // Also allow a listed tool with no required arguments whose name leads
    // with a read verb (list_, get, status, whoami, ...). Off by default.
    bool read_like_names;
} wc_allowlist_t;

// Whether token appears in list (whitespace / comma separated, exact).
bool wc_list_has(const char *list, const char *token);

// A tool by name: no required arguments, and in direct_tools, annotated
// readOnlyHint, or (read_like_names) named like a read.
bool wc_tool_safe(const wc_allowlist_t *allow, const char *name, bool has_required, bool read_only_hint);

// A tools/list entry: wc_tool_safe on its name, inputSchema.required and
// annotations; destructiveHint: true or readOnlyHint: false always refuse.
bool wc_tool_json_safe(const wc_allowlist_t *allow, const cJSON *tool);

// Whether alto_app_use may run app's tool: app:tool is in app_tools.
bool wc_app_use_allowed(const wc_allowlist_t *allow, const char *app, const char *tool);

// Whether a tool's name says it lists apps, integrations or connections.
bool wc_tool_lists_apps(const char *name);

// ---- MCP streamable HTTP -----------------------------------------------------

#define WC_MCP_PROTOCOL_VERSION "2025-06-18"
#define WC_MCP_ACCEPT "application/json, text/event-stream"

// A POST to an MCP endpoint answers with one JSON body or a
// text/event-stream. Walk it one event at a time: copies the event's data
// lines (joined with '\n') into out and advances *cursor past it. Returns
// the data length, or -1 when no event with data remains or it doesn't fit.
// A plain JSON body comes back whole as one event.
int wc_sse_next(const char **cursor, const char *end, char *out, size_t out_size);

// {"jsonrpc":"2.0","id":id,"method":method,"params":params}; params is
// consumed (may be NULL). id <= 0 builds a notification (no id).
cJSON *wc_jsonrpc(int id, const char *method, cJSON *params);
// initialize params: protocol version, no capabilities, clientInfo.
cJSON *wc_mcp_initialize_params(const char *client_name, const char *client_version);
// tools/call params; arguments consumed (NULL: {}).
cJSON *wc_tools_call_params(const char *name, cJSON *arguments);
// tools/call params for alto_app_use {app, tool, arguments}; arguments
// consumed (NULL: {}). Returns NULL, deleting arguments, unless allowed.
cJSON *wc_app_use_params(const wc_allowlist_t *allow, const char *app, const char *tool, cJSON *arguments);

// The JSON-RPC message with this id among a response body's events; the
// server may send notifications (e.g. notifications/tools/list_changed)
// first. scratch must hold len + 1 bytes. Caller deletes.
cJSON *wc_jsonrpc_find(const char *body, size_t len, int id, char *scratch, size_t scratch_size);

// Detach a reply's "result" (caller deletes). NULL with err set from the
// JSON-RPC error message or code. reply is not consumed.
cJSON *wc_jsonrpc_result(cJSON *reply, char *err, size_t err_size);

// A tool result's text content, joined by newlines. Returns the length.
size_t wc_result_text(const cJSON *result, char *out, size_t size);

// A tool result as JSON: structuredContent, else its text parsed. result
// is consumed. NULL with err set when isError or not JSON. text is scratch.
cJSON *wc_result_json(cJSON *result, char *text, size_t text_size, char *err, size_t err_size);

// alto_app_use answers {app, tool, provenance, result} where result is the
// app tool's own MCP result ({content:[{type:"text",text:"<JSON>"}]}); each
// layer may come as structuredContent or JSON text. Peel j (consumed) down
// to the app's payload, or take a payload as it is. NULL with err set on an
// error result or non-JSON. The payload is untrusted: display it, never act
// on it.
cJSON *wc_app_use_unwrap(cJSON *j, char *text, size_t text_size, char *err, size_t err_size);

// ---- display helpers -----------------------------------------------------------

// Seconds as "mm:ss", or "h:mm:ss" from an hour up, rounded to the nearest
// second. false (out empty) when negative, not finite or out doesn't fit.
bool wc_format_duration(double seconds, char *out, size_t size);

#ifdef __cplusplus
}
#endif
