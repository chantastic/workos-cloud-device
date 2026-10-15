// One HTTPS request with the ESP-IDF certificate bundle and the configured
// User-Agent. Never logs headers or bodies: they can carry tokens.
#pragma once
#include <stdbool.h>
#include <stddef.h>

#include "cJSON.h"

typedef struct {
    const char *url;
    const char *method;         // "GET", "POST", "DELETE"; NULL: POST with a body, else GET
    const char *body;           // NULL: none
    const char *content_type;   // with body; NULL: application/json
    const char *accept;         // NULL: application/json
    const char *bearer;         // access token or NULL
    const char *mcp_session;    // sends Mcp-Session-Id and MCP-Protocol-Version when set
    char *mcp_session_out;      // receives a response Mcp-Session-Id, if any
    size_t mcp_session_out_size;
    size_t max_response;        // 0: 32 KiB
} wc_http_request_t;

typedef struct {
    int status;       // HTTP status, 0 when there was no response
    char *body;       // PSRAM when present, NUL-terminated; NULL when empty
    size_t len;
    bool truncated;   // the body hit max_response
    bool event_stream;
} wc_http_response_t;

bool wc_http_send(const wc_http_request_t *req, wc_http_response_t *res);
void wc_http_response_free(wc_http_response_t *res);   // wipes the body

// POST an application/x-www-form-urlencoded body; parse a JSON reply.
cJSON *wc_http_form(const char *url, const char *form, int *status);
// GET with a bearer; parse a JSON reply.
cJSON *wc_http_get_json(const char *url, const char *bearer, int *status);

// Big buffers go to PSRAM when there is any, else internal RAM.
void *wc_alloc(size_t size);   // zeroed
void wc_wipe_free(void *p, size_t size);
