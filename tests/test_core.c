// Host tests for components/workos_cloud/core. No ESP-IDF, no board.
// Run: make test
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "workos_cloud_core.h"

static int failures, checks;
#define CHECK(cond)                                                              \
    do {                                                                         \
        checks++;                                                                \
        if (!(cond)) {                                                           \
            failures++;                                                          \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
        }                                                                        \
    } while (0)

static const wc_allowlist_t ALLOW = {
    .direct_tools = "alto_whoami alto_apps_available,alto_integrations_list",
    .app_tools = "video:list_videos video:get_video_status",
};

// ---- device grant -------------------------------------------------------

static void test_grant(void)
{
    CHECK(wc_grant_classify(200, NULL, true) == WC_GRANT_SUCCESS);
    CHECK(wc_grant_classify(200, NULL, false) == WC_GRANT_FAILED);
    CHECK(wc_grant_classify(400, "authorization_pending", false) == WC_GRANT_PENDING);
    CHECK(wc_grant_classify(400, "slow_down", false) == WC_GRANT_SLOW_DOWN);
    CHECK(wc_grant_classify(400, "access_denied", false) == WC_GRANT_DENIED);
    CHECK(wc_grant_classify(400, "expired_token", false) == WC_GRANT_EXPIRED);
    CHECK(wc_grant_classify(400, "invalid_grant", false) == WC_GRANT_FAILED);
    CHECK(wc_grant_classify(400, "invalid_target", false) == WC_GRANT_FAILED);   // resource not enrolled
    CHECK(wc_grant_classify(400, NULL, false) == WC_GRANT_FAILED);
    CHECK(wc_grant_classify(0, NULL, false) == WC_GRANT_NETWORK);
    CHECK(wc_grant_classify(503, NULL, false) == WC_GRANT_NETWORK);
    CHECK(wc_grant_classify(429, NULL, false) == WC_GRANT_NETWORK);
    CHECK(!strcmp(wc_grant_name(WC_GRANT_SLOW_DOWN), "slow_down"));

    wc_poll_t p;
    wc_poll_start(&p, 1000, 5, 300);
    CHECK(!wc_poll_due(&p, 5999));
    CHECK(wc_poll_due(&p, 6000));
    CHECK(wc_poll_after(&p, 6000, WC_GRANT_PENDING));
    CHECK(p.next_ms == 11000);
    CHECK(wc_poll_after(&p, 11000, WC_GRANT_SLOW_DOWN));
    CHECK(p.interval_s == 10 && p.next_ms == 21000);
    CHECK(wc_poll_after(&p, 21000, WC_GRANT_NETWORK));
    CHECK(p.interval_s == 10);
    CHECK(!wc_poll_after(&p, 22000, WC_GRANT_DENIED));
    CHECK(!wc_poll_after(&p, 22000, WC_GRANT_SUCCESS));
    CHECK(!wc_poll_after(&p, 301000, WC_GRANT_PENDING));   // past the deadline
    CHECK(wc_poll_expired(&p, 301000));

    wc_poll_start(&p, 0, 0, 0);
    CHECK(p.interval_s == WC_POLL_DEFAULT_INTERVAL_S && p.deadline_ms == 300000);
    wc_poll_start(&p, 0, 500, 60);
    CHECK(p.interval_s == WC_POLL_MAX_INTERVAL_S);
    for (int i = 0; i < 20; i++) wc_poll_after(&p, 0, WC_GRANT_SLOW_DOWN);
    CHECK(p.interval_s == WC_POLL_MAX_INTERVAL_S);

    // Survives clock wraparound.
    wc_poll_start(&p, 0xFFFFF000u, 5, 300);
    CHECK(!wc_poll_due(&p, 0xFFFFF000u + 4999));
    CHECK(wc_poll_due(&p, 0xFFFFF000u + 5000));
    CHECK(!wc_poll_expired(&p, 0xFFFFF000u + 299999));

    // {"sub":"user_1","exp":42} as an unpadded base64url payload.
    char out[128];
    int n = wc_jwt_payload("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyXzEiLCJleHAiOjQyfQ.sig", out, sizeof(out));
    CHECK(n > 0 && !strcmp(out, "{\"sub\":\"user_1\",\"exp\":42}"));
    CHECK(wc_jwt_payload("no-dots", out, sizeof(out)) == -1);
    CHECK(wc_jwt_payload("a.b!d.c", out, sizeof(out)) == -1);
    CHECK(wc_jwt_payload("a.eyJzdWIiOiJ1c2VyXzEiLCJleHAiOjQyfQ.c", out, 8) == -1);
}

// ---- session and form bodies -------------------------------------------

static void test_session(void)
{
    CHECK(wc_session_renew_in(300, 0, 0) == 255);
    CHECK(wc_session_renew_in(0, 1000 + 3600, 1000) == 3555);   // exp - iat
    CHECK(wc_session_renew_in(0, 42, 0) == 255);                 // no iat: default
    CHECK(wc_session_renew_in(30, 0, 0) == 15);                  // floor
    CHECK(wc_session_renew_in(10 * 86400, 0, 0) == 86400 - 45);  // cap

    char f[128] = "";
    CHECK(wc_form_add(f, sizeof(f), "client_id", "client_01ABC"));
    CHECK(wc_form_add(f, sizeof(f), "scope", "openid profile"));
    CHECK(wc_form_add(f, sizeof(f), "resource", "https://mcp.workos.cloud/mcp"));
    CHECK(!strcmp(f, "client_id=client_01ABC&scope=openid%20profile&resource=https%3A%2F%2Fmcp.workos.cloud%2Fmcp"));
    char g[24] = "";
    CHECK(wc_form_add(g, sizeof(g), "a", "b~c-d.e_f"));
    CHECK(!strcmp(g, "a=b~c-d.e_f"));
    CHECK(!wc_form_add(g, sizeof(g), "refresh_token", "x+y/z"));   // would not fit
    CHECK(!strcmp(g, "a=b~c-d.e_f"));
    char h[9] = "";   // exactly fits
    CHECK(wc_form_add(h, sizeof(h), "k", "\xff&"));
    CHECK(!strcmp(h, "k=%FF%26"));
}

static void test_tokens(void)
{
    char scratch[256];
    wc_tokens_t t;
    // JWT payload {"exp":1300,"iat":1000}: lifetime 300 when expires_in is absent.
    cJSON *r = cJSON_Parse("{\"access_token\":\"h.eyJleHAiOjEzMDAsImlhdCI6MTAwMH0.s\",\"token_type\":\"Bearer\","
                           "\"refresh_token\":\"rt_1\"}");
    CHECK(wc_tokens_parse(r, 1024, scratch, sizeof(scratch), &t));
    CHECK(t.lifetime_s == 300 && t.renew_in_s == 255 && t.refresh_token && !strcmp(t.refresh_token, "rt_1"));
    CHECK(scratch[0] == 0);   // wiped
    cJSON_Delete(r);

    r = cJSON_Parse("{\"access_token\":\"x.y.z\",\"expires_in\":300}");
    CHECK(wc_tokens_parse(r, 1024, scratch, sizeof(scratch), &t) && t.lifetime_s == 300 && !t.refresh_token);
    CHECK(!wc_tokens_parse(r, 5, scratch, sizeof(scratch), &t));   // too long for the buffer
    cJSON_Delete(r);
    r = cJSON_Parse("{\"access_token\":\"x.y.z\",\"token_type\":\"mac\"}");
    CHECK(!wc_tokens_parse(r, 1024, scratch, sizeof(scratch), &t));
    cJSON_Delete(r);
    r = cJSON_Parse("{\"access_token\":\"\"}");
    CHECK(!wc_tokens_parse(r, 1024, scratch, sizeof(scratch), &t));
    cJSON_Delete(r);
    CHECK(!wc_tokens_parse(NULL, 1024, scratch, sizeof(scratch), &t));

    wc_device_auth_t d;
    r = cJSON_Parse("{\"device_code\":\"dc\",\"user_code\":\"ABCD-EFGH\",\"verification_uri\":\"https://signin.workos.com/device\","
                    "\"verification_uri_complete\":\"https://signin.workos.com/device?user_code=ABCD-EFGH\","
                    "\"interval\":5,\"expires_in\":600}");
    CHECK(wc_device_auth_parse(r, &d) && d.interval_s == 5 && d.expires_in_s == 600);
    CHECK(!strcmp(d.verification_uri, "https://signin.workos.com/device?user_code=ABCD-EFGH"));
    cJSON_Delete(r);
    r = cJSON_Parse("{\"device_code\":\"dc\",\"user_code\":\"A\",\"verification_uri\":\"http://evil/\"}");
    CHECK(!wc_device_auth_parse(r, &d));   // https only
    cJSON_Delete(r);
}

// ---- allowlist ----------------------------------------------------------

static void test_allowlist(void)
{
    CHECK(wc_list_has("a b,c\td", "c") && wc_list_has("a b,c\td", "d") && !wc_list_has("ab", "a"));
    CHECK(!wc_list_has("a", "") && !wc_list_has(NULL, "a") && !wc_list_has("", "a"));

    CHECK(wc_tool_safe(&ALLOW, "alto_apps_available", false, false));
    CHECK(wc_tool_safe(&ALLOW, "alto_integrations_list", false, false));
    CHECK(wc_tool_safe(&ALLOW, "alto_whoami", false, false));
    CHECK(!wc_tool_safe(&ALLOW, "alto_apps_available", true, false));   // required arguments
    CHECK(!wc_tool_safe(&ALLOW, "alto_apps_connect", false, false));
    CHECK(!wc_tool_safe(&ALLOW, "alto_app_use", true, false));          // dispatcher: required args, destructive
    CHECK(wc_tool_safe(&ALLOW, "render_video", false, true));           // annotated read-only
    CHECK(!wc_tool_safe(&ALLOW, "list_apps", false, false));            // names alone: off by default
    CHECK(!wc_tool_safe(&ALLOW, "", false, true));
    CHECK(!wc_tool_safe(NULL, "alto_whoami", false, false));

    wc_allowlist_t names = ALLOW;
    names.read_like_names = true;
    CHECK(wc_tool_safe(&names, "list_apps", false, false));
    CHECK(wc_tool_safe(&names, "getStatus", false, false));
    CHECK(wc_tool_safe(&names, "video-status", false, false));
    CHECK(wc_tool_safe(&names, "whoami", false, false));
    CHECK(!wc_tool_safe(&names, "list_apps", true, true));
    CHECK(!wc_tool_safe(&names, "delete_app", false, false));
    CHECK(!wc_tool_safe(&names, "upload_list", false, false));   // verb must lead

    cJSON *t = cJSON_Parse("{\"name\":\"alto_whoami\",\"inputSchema\":{\"type\":\"object\"}}");
    CHECK(wc_tool_json_safe(&ALLOW, t));
    cJSON_Delete(t);
    t = cJSON_Parse("{\"name\":\"alto_whoami\",\"annotations\":{\"readOnlyHint\":false}}");
    CHECK(!wc_tool_json_safe(&ALLOW, t));   // explicit false outranks the list
    cJSON_Delete(t);
    t = cJSON_Parse("{\"name\":\"x\",\"annotations\":{\"readOnlyHint\":true,\"destructiveHint\":true}}");
    CHECK(!wc_tool_json_safe(&ALLOW, t));
    cJSON_Delete(t);
    t = cJSON_Parse("{\"name\":\"alto_app_use\",\"inputSchema\":{\"required\":[\"app\",\"tool\"]},"
                    "\"annotations\":{\"destructiveHint\":true}}");
    CHECK(!wc_tool_json_safe(&ALLOW, t));
    cJSON_Delete(t);
    t = cJSON_Parse("{\"name\":\"peek\",\"inputSchema\":{\"required\":[]},\"annotations\":{\"readOnlyHint\":true}}");
    CHECK(wc_tool_json_safe(&ALLOW, t));   // empty required list
    cJSON_Delete(t);

    // alto_app_use: only the listed pairs, exactly.
    CHECK(wc_app_use_allowed(&ALLOW, "video", "list_videos"));
    CHECK(wc_app_use_allowed(&ALLOW, "video", "get_video_status"));
    CHECK(!wc_app_use_allowed(&ALLOW, "video", "delete_video"));
    CHECK(!wc_app_use_allowed(&ALLOW, "video", "upload_video"));
    CHECK(!wc_app_use_allowed(&ALLOW, "video", "list_videos "));
    CHECK(!wc_app_use_allowed(&ALLOW, "video", "LIST_VIDEOS"));
    CHECK(!wc_app_use_allowed(&ALLOW, "video", ""));
    CHECK(!wc_app_use_allowed(&ALLOW, "video", NULL));
    CHECK(!wc_app_use_allowed(&ALLOW, "video--staging", "list_videos"));
    CHECK(!wc_app_use_allowed(&ALLOW, "flashboard", "list_videos"));
    CHECK(!wc_app_use_allowed(&ALLOW, NULL, "list_videos"));
    CHECK(!wc_app_use_allowed(&ALLOW, "video:list_videos", ""));
    CHECK(!wc_app_use_allowed(&ALLOW, "", "video:list_videos"));
    wc_allowlist_t none = { 0 };
    CHECK(!wc_app_use_allowed(&none, "video", "list_videos"));

    CHECK(wc_tool_lists_apps("list_apps"));
    CHECK(wc_tool_lists_apps("listIntegrations"));
    CHECK(wc_tool_lists_apps("get-connections"));
    CHECK(wc_tool_lists_apps("app"));
    CHECK(!wc_tool_lists_apps("approve_request"));
    CHECK(!wc_tool_lists_apps("list_users"));
    CHECK(wc_tool_lists_apps("alto_apps_available"));
    CHECK(wc_tool_lists_apps("alto_integrations_list"));
}

// ---- MCP ----------------------------------------------------------------

static char *print(const cJSON *j)
{
    static char buf[512];
    char *s = cJSON_PrintUnformatted(j);
    snprintf(buf, sizeof(buf), "%s", s ? s : "");
    free(s);
    return buf;
}

static void test_sse(void)
{
    char out[128];
    const char *json = "  {\"jsonrpc\":\"2.0\",\"id\":1}";
    const char *c = json;
    CHECK(wc_sse_next(&c, json + strlen(json), out, sizeof(out)) > 0 && !strcmp(out, "{\"jsonrpc\":\"2.0\",\"id\":1}"));
    CHECK(wc_sse_next(&c, json + strlen(json), out, sizeof(out)) == -1);

    const char *sse = "event: message\r\nid: 7\r\ndata: {\"a\":1}\r\n\r\n: keepalive\n\n"
                      "event: message\ndata: {\"b\":\ndata: 2}\n\ndata:{\"c\":3}";
    const char *end = sse + strlen(sse);
    c = sse;
    CHECK(wc_sse_next(&c, end, out, sizeof(out)) == 7 && !strcmp(out, "{\"a\":1}"));
    CHECK(wc_sse_next(&c, end, out, sizeof(out)) > 0 && !strcmp(out, "{\"b\":\n2}"));
    CHECK(wc_sse_next(&c, end, out, sizeof(out)) > 0 && !strcmp(out, "{\"c\":3}"));   // unterminated last event
    CHECK(wc_sse_next(&c, end, out, sizeof(out)) == -1);
    c = sse;
    CHECK(wc_sse_next(&c, end, out, 4) == -1);   // too big for out
    const char *empty = "event: ping\n\n";
    c = empty;
    CHECK(wc_sse_next(&c, empty + strlen(empty), out, sizeof(out)) == -1);
}

static void test_jsonrpc(void)
{
    cJSON *m = wc_jsonrpc(1, "initialize", wc_mcp_initialize_params("dev", "1.0"));
    CHECK(!strcmp(print(m), "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":"
                            "\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"dev\",\"version\":\"1.0\"}}}"));
    cJSON_Delete(m);
    m = wc_jsonrpc(0, "notifications/initialized", NULL);
    CHECK(!strcmp(print(m), "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}"));
    cJSON_Delete(m);
    m = wc_jsonrpc(3, "tools/call", wc_tools_call_params("alto_whoami", NULL));
    CHECK(!strcmp(print(m), "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"alto_whoami\","
                            "\"arguments\":{}}}"));
    cJSON_Delete(m);

    cJSON *args = cJSON_CreateObject();
    cJSON_AddNumberToObject(args, "limit", 1);
    cJSON *p = wc_app_use_params(&ALLOW, "video", "list_videos", args);
    CHECK(!strcmp(print(p), "{\"name\":\"alto_app_use\",\"arguments\":{\"app\":\"video\",\"tool\":\"list_videos\","
                            "\"arguments\":{\"limit\":1}}}"));
    cJSON_Delete(p);
    CHECK(wc_app_use_params(&ALLOW, "video", "delete_video", cJSON_CreateObject()) == NULL);   // args freed (ASan)

    // A list_changed notification arrives before the reply: match by id.
    const char *body = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n"
                       "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n";
    char scratch[512];
    cJSON *reply = wc_jsonrpc_find(body, strlen(body), 2, scratch, sizeof(scratch));
    CHECK(reply == NULL);
    reply = wc_jsonrpc_find(body, strlen(body), 1, scratch, sizeof(scratch));
    char err[64] = "";
    cJSON *result = wc_jsonrpc_result(reply, err, sizeof(err));
    CHECK(result && cJSON_IsTrue(cJSON_GetObjectItem(result, "ok")) && !err[0]);
    cJSON_Delete(result);
    cJSON_Delete(reply);

    reply = cJSON_Parse("{\"jsonrpc\":\"2.0\",\"id\":4,\"error\":{\"code\":-32602,\"message\":\"Unknown tool\"}}");
    CHECK(!wc_jsonrpc_result(reply, err, sizeof(err)) && !strcmp(err, "Unknown tool"));
    cJSON_Delete(reply);
    reply = cJSON_Parse("{\"jsonrpc\":\"2.0\",\"id\":4,\"error\":{\"code\":-32601}}");
    CHECK(!wc_jsonrpc_result(reply, err, sizeof(err)) && !strcmp(err, "JSON-RPC error -32601"));
    cJSON_Delete(reply);
}

static void test_results(void)
{
    char text[256], err[64];
    cJSON *r = cJSON_Parse("{\"content\":[{\"type\":\"text\",\"text\":\"one\"},{\"type\":\"image\"},{\"text\":\"two\"}]}");
    CHECK(wc_result_text(r, text, sizeof(text)) == 7 && !strcmp(text, "one\ntwo"));
    CHECK(wc_result_text(r, text, 4) == 3 && !strcmp(text, "one"));
    CHECK(wc_result_text(r, text, 3) == 2 && !strcmp(text, "on"));
    cJSON_Delete(r);

    r = cJSON_Parse("{\"content\":[{\"text\":\"{\\\"user\\\":{\\\"email\\\":\\\"a@b\\\"}}\"}]}");
    cJSON *j = wc_result_json(r, text, sizeof(text), err, sizeof(err));
    CHECK(j && !strcmp(print(j), "{\"user\":{\"email\":\"a@b\"}}"));
    cJSON_Delete(j);
    r = cJSON_Parse("{\"structuredContent\":{\"apps\":[]},\"content\":[{\"text\":\"ignored\"}]}");
    j = wc_result_json(r, text, sizeof(text), err, sizeof(err));
    CHECK(j && !strcmp(print(j), "{\"apps\":[]}"));
    cJSON_Delete(j);
    r = cJSON_Parse("{\"isError\":true,\"content\":[{\"text\":\"forbidden\"}]}");
    CHECK(!wc_result_json(r, text, sizeof(text), err, sizeof(err)) && !strcmp(err, "forbidden"));
    r = cJSON_Parse("{\"content\":[{\"text\":\"plain words\"}]}");
    CHECK(!wc_result_json(r, text, sizeof(text), err, sizeof(err)) && !strcmp(err, "not JSON"));
}

static void test_unwrap(void)
{
    char text[512], err[64];
    // The live shape: a tool result whose text is the wrapper, whose result
    // is the app tool's result, whose text is the payload.
    const char *payload = "{\"videos\":[{\"videoId\":\"v1\",\"title\":\"T\"}],\"nextOffset\":1}";
    cJSON *inner = cJSON_CreateObject();
    cJSON *content = cJSON_AddArrayToObject(inner, "content");
    cJSON *item = cJSON_CreateObject();
    cJSON_AddStringToObject(item, "type", "text");
    cJSON_AddStringToObject(item, "text", payload);
    cJSON_AddItemToArray(content, item);
    cJSON *wrapper = cJSON_CreateObject();
    cJSON_AddStringToObject(wrapper, "app", "video");
    cJSON_AddStringToObject(wrapper, "tool", "list_videos");
    cJSON_AddItemToObject(wrapper, "provenance", cJSON_CreateObject());
    cJSON_AddItemToObject(wrapper, "result", inner);
    char *wrapper_text = cJSON_PrintUnformatted(wrapper);
    cJSON_Delete(wrapper);
    cJSON *outer = cJSON_CreateObject();
    item = cJSON_CreateObject();
    cJSON_AddStringToObject(item, "type", "text");
    cJSON_AddStringToObject(item, "text", wrapper_text);
    cJSON_AddItemToArray(cJSON_AddArrayToObject(outer, "content"), item);
    free(wrapper_text);

    cJSON *j = wc_app_use_unwrap(outer, text, sizeof(text), err, sizeof(err));
    CHECK(j && !strcmp(print(j), payload));
    cJSON_Delete(j);

    // structuredContent wrapper with result as a JSON string.
    j = cJSON_Parse("{\"structuredContent\":{\"app\":\"video\",\"tool\":\"get_video_status\",\"provenance\":{},"
                    "\"result\":\"{\\\"content\\\":[{\\\"text\\\":\\\"{\\\\\\\"id\\\\\\\":\\\\\\\"v1\\\\\\\"}\\\"}]}\"}}");
    CHECK(j != NULL);
    j = wc_app_use_unwrap(j, text, sizeof(text), err, sizeof(err));
    CHECK(j && !strcmp(print(j), "{\"id\":\"v1\"}"));
    cJSON_Delete(j);

    // A payload given unwrapped is taken as it is.
    j = wc_app_use_unwrap(cJSON_Parse("{\"videos\":[]}"), text, sizeof(text), err, sizeof(err));
    CHECK(j && cJSON_IsArray(cJSON_GetObjectItem(j, "videos")));
    cJSON_Delete(j);

    // The app tool's error surfaces as err.
    err[0] = 0;
    j = cJSON_Parse("{\"app\":\"video\",\"tool\":\"get_video_status\",\"provenance\":{},"
                    "\"result\":{\"isError\":true,\"content\":[{\"text\":\"not found\"}]}}");
    CHECK(!wc_app_use_unwrap(j, text, sizeof(text), err, sizeof(err)) && !strcmp(err, "not found"));
    j = cJSON_Parse("{\"app\":\"video\",\"tool\":\"t\",\"result\":\"not json\"}");
    CHECK(!wc_app_use_unwrap(j, text, sizeof(text), err, sizeof(err)) && !strcmp(err, "not JSON"));

    // Self-similar nesting stops.
    const char *deep = "{\"tool\":\"t\",\"result\":{\"tool\":\"t\",\"result\":{\"tool\":\"t\",\"result\":{\"tool\":\"t\","
                       "\"result\":{\"tool\":\"t\",\"result\":{\"tool\":\"t\",\"result\":{\"tool\":\"t\",\"result\":{}}}}}}}}";
    CHECK(!wc_app_use_unwrap(cJSON_Parse(deep), text, sizeof(text), err, sizeof(err)) && !strcmp(err, "nested too deep"));
    CHECK(!wc_app_use_unwrap(NULL, text, sizeof(text), err, sizeof(err)));
}

static void test_duration(void)
{
    char d[16];
    CHECK(wc_format_duration(0, d, sizeof(d)) && !strcmp(d, "00:00"));
    CHECK(wc_format_duration(187.4, d, sizeof(d)) && !strcmp(d, "03:07"));
    CHECK(wc_format_duration(3599.6, d, sizeof(d)) && !strcmp(d, "1:00:00"));   // rounds up into hours
    CHECK(wc_format_duration(3725, d, sizeof(d)) && !strcmp(d, "1:02:05"));
    CHECK(wc_format_duration(36000, d, sizeof(d)) && !strcmp(d, "10:00:00"));
    CHECK(!wc_format_duration(-1, d, sizeof(d)) && !d[0]);
    CHECK(!wc_format_duration(NAN, d, sizeof(d)) && !d[0]);
    CHECK(!wc_format_duration(INFINITY, d, sizeof(d)));
    CHECK(!wc_format_duration(3725, d, 7) && !d[0]);   // "1:02:05" needs 8
}

int main(void)
{
    test_grant();
    test_session();
    test_tokens();
    test_allowlist();
    test_sse();
    test_jsonrpc();
    test_results();
    test_unwrap();
    test_duration();
    printf("%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
