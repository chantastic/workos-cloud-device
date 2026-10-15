#include "wc_http.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "esp_crt_bundle.h"
#include "esp_heap_caps.h"
#include "esp_http_client.h"

#include "workos_cloud.h"

#define DEFAULT_MAX_RESPONSE (32 * 1024)

void *wc_alloc(size_t size)
{
    void *p = heap_caps_calloc_prefer(1, size, 2, MALLOC_CAP_SPIRAM, MALLOC_CAP_DEFAULT);
    return p;
}

void wc_wipe_free(void *p, size_t size)
{
    if (!p) return;
    memset(p, 0, size);
    free(p);
}

typedef struct {
    const wc_http_request_t *req;
    bool event_stream;
} ctx_t;

static esp_err_t on_event(esp_http_client_event_t *e)
{
    ctx_t *ctx = e->user_data;
    if (e->event_id != HTTP_EVENT_ON_HEADER || !ctx) return ESP_OK;
    if (!strcasecmp(e->header_key, "Mcp-Session-Id") && ctx->req->mcp_session_out &&
        strlen(e->header_value) < ctx->req->mcp_session_out_size)
        strlcpy(ctx->req->mcp_session_out, e->header_value, ctx->req->mcp_session_out_size);
    if (!strcasecmp(e->header_key, "Content-Type") && strstr(e->header_value, "text/event-stream"))
        ctx->event_stream = true;
    return ESP_OK;
}

static esp_http_client_method_t method_of(const wc_http_request_t *req)
{
    if (!req->method) return req->body ? HTTP_METHOD_POST : HTTP_METHOD_GET;
    if (!strcmp(req->method, "DELETE")) return HTTP_METHOD_DELETE;
    if (!strcmp(req->method, "GET")) return HTTP_METHOD_GET;
    return HTTP_METHOD_POST;
}

bool wc_http_send(const wc_http_request_t *req, wc_http_response_t *res)
{
    memset(res, 0, sizeof(*res));
    const wc_config_t *cfg = wc_config();
    ctx_t ctx = { .req = req };
    esp_http_client_config_t hc = {
        .url = req->url,
        .method = method_of(req),
        .user_agent = cfg->user_agent,   // Cloudflare (error 1010) blocks library defaults
        .crt_bundle_attach = esp_crt_bundle_attach,
        .timeout_ms = cfg->timeout_ms,
        .buffer_size = 2048,
        .buffer_size_tx = 4096,
        .disable_auto_redirect = true,
        .event_handler = on_event,
        .user_data = &ctx,
    };
    esp_http_client_handle_t h = esp_http_client_init(&hc);
    if (!h) return false;
    size_t max = req->max_response ? req->max_response : DEFAULT_MAX_RESPONSE;
    char *auth = NULL;
    size_t auth_size = 0;
    char *buf = heap_caps_malloc_prefer(max + 1, 2, MALLOC_CAP_SPIRAM, MALLOC_CAP_DEFAULT);
    bool ok = false;
    if (!buf) goto done;
    if (req->bearer) {
        auth_size = strlen(req->bearer) + 8;
        auth = wc_alloc(auth_size);
        if (!auth) goto done;
        snprintf(auth, auth_size, "Bearer %s", req->bearer);
        esp_http_client_set_header(h, "Authorization", auth);
    }
    esp_http_client_set_header(h, "Accept", req->accept ? req->accept : "application/json");
    if (req->body) esp_http_client_set_header(h, "Content-Type", req->content_type ? req->content_type : "application/json");
    if (req->mcp_session) {
        if (req->mcp_session[0]) esp_http_client_set_header(h, "Mcp-Session-Id", req->mcp_session);
        esp_http_client_set_header(h, "MCP-Protocol-Version", WC_MCP_PROTOCOL_VERSION);
    }
    size_t len = req->body ? strlen(req->body) : 0;
    if (esp_http_client_open(h, len) != ESP_OK) goto done;
    if (len && esp_http_client_write(h, req->body, len) != (int)len) goto done;
    if (esp_http_client_fetch_headers(h) < 0) goto done;
    res->status = esp_http_client_get_status_code(h);
    res->event_stream = ctx.event_stream;
    size_t got = 0;
    while (got < max) {
        int n = esp_http_client_read(h, buf + got, max - got);
        if (n <= 0) break;   // done, closed, or timed out: keep what arrived
        got += n;
        if (esp_http_client_is_complete_data_received(h)) break;
        // An MCP server may hold an event stream open after its reply; a
        // finished event carrying a JSON-RPC result or error is enough.
        if (ctx.event_stream && got >= 2 && buf[got - 1] == '\n' && (buf[got - 2] == '\n' || buf[got - 2] == '\r')) {
            buf[got] = 0;
            if (strstr(buf, "\"result\"") || strstr(buf, "\"error\"")) break;
        }
    }
    if (got == max) {
        char probe;
        res->truncated = esp_http_client_read(h, &probe, 1) > 0;
    }
    ok = true;
    if (got) {
        buf[got] = 0;
        res->body = buf;
        res->len = got;
        buf = NULL;
    }
done:
    wc_wipe_free(buf, buf ? max + 1 : 0);   // responses can carry tokens
    wc_wipe_free(auth, auth_size);
    esp_http_client_cleanup(h);
    return ok;
}

void wc_http_response_free(wc_http_response_t *res)
{
    wc_wipe_free(res->body, res->len);
    res->body = NULL;
    res->len = 0;
}

static cJSON *parse(wc_http_response_t *res)
{
    cJSON *r = res->body && !res->truncated ? cJSON_ParseWithLength(res->body, res->len) : NULL;
    wc_http_response_free(res);
    return r;
}

cJSON *wc_http_form(const char *url, const char *form, int *status)
{
    wc_http_request_t req = { .url = url, .body = form, .content_type = "application/x-www-form-urlencoded" };
    wc_http_response_t res;
    wc_http_send(&req, &res);
    *status = res.status;
    return parse(&res);
}

cJSON *wc_http_get_json(const char *url, const char *bearer, int *status)
{
    wc_http_request_t req = { .url = url, .bearer = bearer };
    wc_http_response_t res;
    wc_http_send(&req, &res);
    *status = res.status;
    return parse(&res);
}
