// Minimal MCP client over streamable HTTP (protocol 2025-06-18). One POST
// per JSON-RPC message; replies may be plain JSON or an event stream.
// Responses are capped at cfg.max_response. Bearer tokens are passed per
// call, never stored here. Only allowlisted calls leave the device.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"

#include "wc_http.h"
#include "workos_cloud.h"

static const char *TAG = "workos_cloud";

static void set_error(wc_mcp_t *m, const char *fmt, int value)
{
    snprintf(m->error, sizeof(m->error), fmt, value);
}

// POST one message (consumed). For a request (id > 0) find the reply with
// that id among the stream's events; notifications only need a 2xx.
static cJSON *post(wc_mcp_t *m, const char *bearer, cJSON *msg, int id, char *session_out, size_t session_out_size)
{
    const wc_config_t *cfg = wc_config();
    char *body = msg ? cJSON_PrintUnformatted(msg) : NULL;
    cJSON_Delete(msg);
    if (!body) {
        set_error(m, "Out of memory.", 0);
        return NULL;
    }
    wc_http_request_t req = {
        .url = cfg->resource,
        .body = body,
        .accept = WC_MCP_ACCEPT,
        .bearer = bearer,
        .mcp_session = m->session,
        .mcp_session_out = session_out,
        .mcp_session_out_size = session_out_size,
        .max_response = cfg->max_response,
    };
    wc_http_response_t res;
    wc_http_send(&req, &res);
    free(body);
    m->status = res.status;
    cJSON *reply = NULL;
    if (res.status < 200 || res.status >= 300) {
        set_error(m, res.status ? "HTTP %d" : "No response.", res.status);
    } else if (id <= 0) {
        // notification: 202 Accepted, no body
    } else if (res.truncated) {
        set_error(m, "Reply over %d KiB.", (int)(cfg->max_response / 1024));
    } else if (!res.body) {
        set_error(m, "Empty reply (HTTP %d).", res.status);
    } else {
        char *scratch = wc_alloc(res.len + 1);
        reply = wc_jsonrpc_find(res.body, res.len, id, scratch, res.len + 1);
        free(scratch);
        if (!reply) set_error(m, "No reply to request %d.", id);
    }
    wc_http_response_free(&res);
    return reply;
}

static cJSON *request(wc_mcp_t *m, const char *bearer, const char *method, cJSON *params)
{
    int id = ++m->next_id;
    cJSON *reply = post(m, bearer, wc_jsonrpc(id, method, params), id, NULL, 0);
    if (!reply) return NULL;
    cJSON *result = wc_jsonrpc_result(reply, m->error, sizeof(m->error));
    cJSON_Delete(reply);
    return result;
}

bool wc_mcp_open(wc_mcp_t *m, const char *bearer)
{
    const wc_config_t *cfg = wc_config();
    memset(m, 0, sizeof(*m));
    int id = ++m->next_id;
    char session[sizeof(m->session)] = "";
    cJSON *msg = wc_jsonrpc(id, "initialize", wc_mcp_initialize_params(cfg->client_name, cfg->client_version));
    cJSON *reply = post(m, bearer, msg, id, session, sizeof(session));
    cJSON *result = cJSON_GetObjectItem(reply, "result");
    if (!result) {
        if (reply && !m->error[0]) set_error(m, "initialize refused.", 0);
        cJSON_Delete(reply);
        ESP_LOGI(TAG, "mcp initialize http=%d", m->status);
        return false;
    }
    cJSON *name = cJSON_GetObjectItem(cJSON_GetObjectItem(result, "serverInfo"), "name");
    if (cJSON_IsString(name)) strlcpy(m->server, name->valuestring, sizeof(m->server));
    cJSON_Delete(reply);
    strlcpy(m->session, session, sizeof(m->session));
    post(m, bearer, wc_jsonrpc(0, "notifications/initialized", NULL), 0, NULL, 0);
    m->error[0] = 0;   // the notification's status is advisory
    return true;
}

cJSON *wc_mcp_list_tools(wc_mcp_t *m, const char *bearer)
{
    return request(m, bearer, "tools/list", NULL);
}

cJSON *wc_mcp_call_tool(wc_mcp_t *m, const char *bearer, const char *name)
{
    if (!wc_list_has(wc_config()->allowlist.direct_tools, name)) {
        set_error(m, "Not an allowlisted tool.", 0);
        return NULL;
    }
    return request(m, bearer, "tools/call", wc_tools_call_params(name, NULL));
}

cJSON *wc_mcp_call_listed(wc_mcp_t *m, const char *bearer, const cJSON *tool)
{
    cJSON *name = cJSON_GetObjectItem(tool, "name");
    if (!wc_mcp_tool_safe(tool) || !cJSON_IsString(name)) {
        set_error(m, "Not a read-only tool.", 0);
        return NULL;
    }
    return request(m, bearer, "tools/call", wc_tools_call_params(name->valuestring, NULL));
}

cJSON *wc_mcp_app_use(wc_mcp_t *m, const char *bearer, const char *app, const char *tool, cJSON *arguments)
{
    cJSON *params = wc_app_use_params(&wc_config()->allowlist, app, tool, arguments);
    if (!params) {
        set_error(m, "Not a read-only app tool.", 0);
        return NULL;
    }
    return request(m, bearer, "tools/call", params);
}

void wc_mcp_close(wc_mcp_t *m, const char *bearer)
{
    if (!m->session[0]) return;
    wc_http_request_t req = { .url = wc_config()->resource, .method = "DELETE", .bearer = bearer, .mcp_session = m->session };
    wc_http_response_t res;
    wc_http_send(&req, &res);
    wc_http_response_free(&res);
    m->session[0] = 0;
}

bool wc_mcp_tool_safe(const cJSON *tool)
{
    return wc_tool_json_safe(&wc_config()->allowlist, tool);
}
