// The JSON half of the core: token and device-code responses, JSON-RPC
// messages, tool results and the alto_app_use wrapper. cJSON only, no I/O.
#include "workos_cloud_core.h"

#include <stdio.h>
#include <ctype.h>
#include <string.h>

static void set_err(char *err, size_t size, const char *text)
{
    if (err && size) snprintf(err, size, "%s", text);
}

static bool same_ascii_nocase(const char *a, const char *b)
{
    for (; *a && *b; a++, b++)
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return false;
    return *a == *b;
}

static const char *string_of(const cJSON *o, const char *key)
{
    cJSON *v = cJSON_GetObjectItem(o, key);
    return cJSON_IsString(v) ? v->valuestring : NULL;
}

// ---- token endpoint ------------------------------------------------------

bool wc_tokens_parse(const cJSON *r, size_t access_max, char *scratch, size_t scratch_size, wc_tokens_t *out)
{
    memset(out, 0, sizeof(*out));
    const char *access = string_of(r, "access_token");
    const char *refresh = string_of(r, "refresh_token");
    const char *type = string_of(r, "token_type");
    cJSON *expires_in = cJSON_GetObjectItem(r, "expires_in");
    if (!access || !access[0] || strlen(access) >= access_max) return false;
    if (type && !same_ascii_nocase(type, "Bearer")) return false;

    double exp = 0, iat = 0;
    if (scratch && scratch_size && wc_jwt_payload(access, scratch, scratch_size) > 0) {
        cJSON *claims = cJSON_Parse(scratch);
        cJSON *e = cJSON_GetObjectItem(claims, "exp"), *i = cJSON_GetObjectItem(claims, "iat");
        if (cJSON_IsNumber(e)) exp = e->valuedouble;
        if (cJSON_IsNumber(i)) iat = i->valuedouble;
        cJSON_Delete(claims);
    }
    if (scratch) memset(scratch, 0, scratch_size);
    int lifetime = cJSON_IsNumber(expires_in) ? expires_in->valueint : 0;
    if (lifetime <= 0 && exp > iat && iat > 0) lifetime = (int)(exp - iat);
    out->access_token = access;
    out->refresh_token = refresh && refresh[0] ? refresh : NULL;
    out->lifetime_s = lifetime > 0 ? lifetime : 0;
    out->renew_in_s = wc_session_renew_in(lifetime, exp, iat);
    return true;
}

bool wc_device_auth_parse(const cJSON *r, wc_device_auth_t *out)
{
    memset(out, 0, sizeof(*out));
    const char *uri = string_of(r, "verification_uri_complete");
    if (!uri) uri = string_of(r, "verification_uri");
    cJSON *interval = cJSON_GetObjectItem(r, "interval"), *expires = cJSON_GetObjectItem(r, "expires_in");
    out->device_code = string_of(r, "device_code");
    out->user_code = string_of(r, "user_code");
    out->verification_uri = uri;
    out->interval_s = cJSON_IsNumber(interval) ? interval->valueint : 0;
    out->expires_in_s = cJSON_IsNumber(expires) ? expires->valueint : 0;
    return out->device_code && out->device_code[0] && out->user_code && out->user_code[0] && uri &&
           !strncmp(uri, "https://", 8);
}

// ---- JSON-RPC ------------------------------------------------------------

cJSON *wc_jsonrpc(int id, const char *method, cJSON *params)
{
    cJSON *msg = cJSON_CreateObject();
    if (!msg) {
        cJSON_Delete(params);
        return NULL;
    }
    cJSON_AddStringToObject(msg, "jsonrpc", "2.0");
    if (id > 0) cJSON_AddNumberToObject(msg, "id", id);
    cJSON_AddStringToObject(msg, "method", method);
    if (params) cJSON_AddItemToObject(msg, "params", params);
    return msg;
}

cJSON *wc_mcp_initialize_params(const char *client_name, const char *client_version)
{
    cJSON *params = cJSON_CreateObject();
    cJSON_AddStringToObject(params, "protocolVersion", WC_MCP_PROTOCOL_VERSION);
    cJSON_AddItemToObject(params, "capabilities", cJSON_CreateObject());
    cJSON *info = cJSON_AddObjectToObject(params, "clientInfo");
    cJSON_AddStringToObject(info, "name", client_name ? client_name : "workos-cloud-device");
    cJSON_AddStringToObject(info, "version", client_version ? client_version : "0.1");
    return params;
}

cJSON *wc_tools_call_params(const char *name, cJSON *arguments)
{
    cJSON *params = cJSON_CreateObject();
    cJSON_AddStringToObject(params, "name", name);
    cJSON_AddItemToObject(params, "arguments", arguments ? arguments : cJSON_CreateObject());
    return params;
}

cJSON *wc_app_use_params(const wc_allowlist_t *allow, const char *app, const char *tool, cJSON *arguments)
{
    if (!wc_app_use_allowed(allow, app, tool)) {
        cJSON_Delete(arguments);
        return NULL;
    }
    cJSON *args = cJSON_CreateObject();
    cJSON_AddStringToObject(args, "app", app);   // "app" here; governance tools say "application"
    cJSON_AddStringToObject(args, "tool", tool);
    cJSON_AddItemToObject(args, "arguments", arguments ? arguments : cJSON_CreateObject());
    return wc_tools_call_params("alto_app_use", args);
}

cJSON *wc_jsonrpc_find(const char *body, size_t len, int id, char *scratch, size_t scratch_size)
{
    if (!body || !scratch) return NULL;
    const char *cursor = body, *end = body + len;
    while (wc_sse_next(&cursor, end, scratch, scratch_size) >= 0) {
        cJSON *j = cJSON_Parse(scratch);
        cJSON *jid = cJSON_GetObjectItem(j, "id");
        if (cJSON_IsNumber(jid) && jid->valueint == id) return j;
        cJSON_Delete(j);   // a notification or a server request: not ours
    }
    return NULL;
}

cJSON *wc_jsonrpc_result(cJSON *reply, char *err, size_t err_size)
{
    cJSON *result = cJSON_DetachItemFromObject(reply, "result");
    if (result) return result;
    cJSON *e = cJSON_GetObjectItem(reply, "error");
    const char *text = string_of(e, "message");
    cJSON *code = cJSON_GetObjectItem(e, "code");
    if (text) {
        set_err(err, err_size, text);
    } else if (err && err_size) {
        snprintf(err, err_size, "JSON-RPC error %d", cJSON_IsNumber(code) ? code->valueint : 0);
    }
    return NULL;
}

// ---- tool results --------------------------------------------------------

bool wc_tool_json_safe(const wc_allowlist_t *allow, const cJSON *tool)
{
    const char *name = string_of(tool, "name");
    cJSON *schema = cJSON_GetObjectItem(tool, "inputSchema");
    cJSON *required = cJSON_GetObjectItem(schema, "required");
    cJSON *ann = cJSON_GetObjectItem(tool, "annotations");
    cJSON *ro = cJSON_GetObjectItem(ann, "readOnlyHint");
    if (!name || cJSON_IsTrue(cJSON_GetObjectItem(ann, "destructiveHint"))) return false;
    // An explicit readOnlyHint: false outranks a name or a list entry.
    if (cJSON_IsFalse(ro)) return false;
    return wc_tool_safe(allow, name, cJSON_IsArray(required) && cJSON_GetArraySize(required) > 0, cJSON_IsTrue(ro));
}

size_t wc_result_text(const cJSON *result, char *out, size_t size)
{
    if (!out || !size) return 0;
    out[0] = 0;
    size_t n = 0;
    cJSON *c;
    cJSON_ArrayForEach(c, cJSON_GetObjectItem(result, "content")) {
        const char *text = string_of(c, "text");
        if (!text) continue;
        if (n && n + 1 < size) out[n++] = '\n';
        size_t len = strlen(text);
        if (n + len >= size) {
            memcpy(out + n, text, size - 1 - n);
            out[size - 1] = 0;
            return size - 1;
        }
        memcpy(out + n, text, len + 1);
        n += len;
    }
    return n;
}

cJSON *wc_result_json(cJSON *result, char *text, size_t text_size, char *err, size_t err_size)
{
    if (!result) return NULL;
    cJSON *j = NULL;
    if (cJSON_IsTrue(cJSON_GetObjectItem(result, "isError"))) {
        wc_result_text(result, text, text_size);
        set_err(err, err_size, text && text[0] ? text : "tool error");
    } else {
        j = cJSON_DetachItemFromObject(result, "structuredContent");
        if (!j) {
            wc_result_text(result, text, text_size);
            j = cJSON_Parse(text);
            if (!j) set_err(err, err_size, "not JSON");
        }
    }
    cJSON_Delete(result);
    return j;
}

cJSON *wc_app_use_unwrap(cJSON *j, char *text, size_t text_size, char *err, size_t err_size)
{
    for (int depth = 0; j && depth < 6; depth++) {
        cJSON *next = NULL, *inner = cJSON_GetObjectItem(j, "result");
        if (cJSON_IsArray(cJSON_GetObjectItem(j, "content")) || cJSON_IsObject(cJSON_GetObjectItem(j, "structuredContent"))) {
            // An MCP tool result (consumed).
            next = wc_result_json(j, text, text_size, err, err_size);
            if (!next) return NULL;
            j = next;
            continue;
        }
        if (inner && (cJSON_GetObjectItem(j, "provenance") || cJSON_IsString(cJSON_GetObjectItem(j, "tool")))) {
            // The alto_app_use wrapper.
            next = cJSON_IsString(inner) ? cJSON_Parse(inner->valuestring) : cJSON_DetachItemFromObject(j, "result");
            if (!next) set_err(err, err_size, "not JSON");
        } else {
            return j;
        }
        cJSON_Delete(j);
        j = next;
    }
    if (j) set_err(err, err_size, "nested too deep");
    cJSON_Delete(j);
    return NULL;
}
