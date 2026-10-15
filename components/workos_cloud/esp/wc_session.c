// Configuration, the saved session (NVS) and the RFC 8628 device grant.
// Tokens are never printed or logged; only HTTP statuses are.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "nvs.h"
#include "sdkconfig.h"

#include "wc_http.h"
#include "workos_cloud.h"

#define ACCESS_MAX 16384
#define REFRESH_MAX 3072   // NVS strings top out near 4000 bytes
#define FORM_MAX 12288
#define DEVICE_GRANT "urn:ietf:params:oauth:grant-type:device_code"

static const char *TAG = "workos_cloud";

static wc_config_t s_cfg;
static char *s_access;           // never printed
static int64_t s_access_until;   // esp_timer µs: renew from here on
static char s_device_code[512];
static wc_poll_t s_poll;

static uint32_t now_ms(void) { return (uint32_t)(esp_timer_get_time() / 1000); }

// ---- configuration ---------------------------------------------------------

void wc_config_default(wc_config_t *cfg)
{
    *cfg = (wc_config_t){
        .auth_server = CONFIG_WORKOS_CLOUD_AUTH_SERVER,
        .resource = CONFIG_WORKOS_CLOUD_RESOURCE,
        .client_id = CONFIG_WORKOS_CLOUD_CLIENT_ID,
        .scope = CONFIG_WORKOS_CLOUD_SCOPE,
        .user_agent = CONFIG_WORKOS_CLOUD_USER_AGENT,
        .client_name = CONFIG_WORKOS_CLOUD_CLIENT_NAME,
        .client_version = "0.1",
        .nvs_namespace = CONFIG_WORKOS_CLOUD_NVS_NAMESPACE,
        .nvs_refresh_key = CONFIG_WORKOS_CLOUD_NVS_REFRESH_KEY,
        .allowlist = {
            .direct_tools = CONFIG_WORKOS_CLOUD_DIRECT_TOOLS,
            .app_tools = CONFIG_WORKOS_CLOUD_APP_TOOLS,
#ifdef CONFIG_WORKOS_CLOUD_READ_LIKE_NAMES
            .read_like_names = true,
#endif
        },
        .max_response = (size_t)CONFIG_WORKOS_CLOUD_MAX_RESPONSE_KB * 1024,
        .timeout_ms = CONFIG_WORKOS_CLOUD_TIMEOUT_MS,
    };
}

static bool one_https_url(const char *s)
{
    if (!s || strncmp(s, "https://", 8) || !s[8]) return false;
    for (; *s; s++)
        if (*s == ' ' || *s == ',' || *s == '\t' || *s == '\n') return false;
    return true;
}

esp_err_t wc_init(const wc_config_t *cfg)
{
    if (!cfg || !cfg->client_id || !cfg->client_id[0] || !one_https_url(cfg->resource) ||
        !one_https_url(cfg->auth_server) || !cfg->scope || !cfg->user_agent || !cfg->user_agent[0] ||
        !cfg->nvs_namespace || !cfg->nvs_refresh_key)
        return ESP_ERR_INVALID_ARG;
    s_cfg = *cfg;
    if (!s_cfg.max_response) s_cfg.max_response = 512 * 1024;
    if (s_cfg.timeout_ms <= 0) s_cfg.timeout_ms = 20000;
    if (!s_access) s_access = wc_alloc(ACCESS_MAX);
    return s_access ? ESP_OK : ESP_ERR_NO_MEM;
}

const wc_config_t *wc_config(void)
{
    return &s_cfg;
}

static void emit(const wc_event_t *e)
{
    if (s_cfg.on_event) s_cfg.on_event(e, s_cfg.ctx);
}

// ---- NVS -------------------------------------------------------------------

static bool load_refresh(char *out, size_t size)
{
    nvs_handle_t h;
    if (nvs_open(s_cfg.nvs_namespace, NVS_READONLY, &h) != ESP_OK) return false;
    bool ok = nvs_get_str(h, s_cfg.nvs_refresh_key, out, &size) == ESP_OK && out[0];
    nvs_close(h);
    return ok;
}

static bool save_refresh(const char *value)
{
    nvs_handle_t h;
    if (strlen(value) >= REFRESH_MAX || nvs_open(s_cfg.nvs_namespace, NVS_READWRITE, &h) != ESP_OK) return false;
    bool ok = nvs_set_str(h, s_cfg.nvs_refresh_key, value) == ESP_OK && nvs_commit(h) == ESP_OK;
    nvs_close(h);
    return ok;
}

static void erase_refresh(void)
{
    nvs_handle_t h;
    if (nvs_open(s_cfg.nvs_namespace, NVS_READWRITE, &h) != ESP_OK) return;
    if (nvs_erase_key(h, s_cfg.nvs_refresh_key) == ESP_OK) nvs_commit(h);
    nvs_close(h);
}

// ---- session ---------------------------------------------------------------

bool wc_has_saved_session(void)
{
    char *refresh = wc_alloc(REFRESH_MAX);
    bool ok = refresh && load_refresh(refresh, REFRESH_MAX);
    wc_wipe_free(refresh, REFRESH_MAX);
    return ok;
}

void wc_forget(void)
{
    erase_refresh();
    if (s_access) memset(s_access, 0, ACCESS_MAX);
    s_access_until = 0;
}

void wc_expire_access(void)
{
    s_access_until = 0;
}

bool wc_status_rejected(int status)
{
    return status != 0 && status != -1 && status < 500 && status != 429;
}

// A token-endpoint form: the grant, its credential, the public client and
// the one resource. Free with wc_wipe_free(FORM_MAX).
static char *token_form(const char *grant, const char *key, const char *value)
{
    char *f = wc_alloc(FORM_MAX);
    if (!f) return NULL;
    bool ok = (!grant || wc_form_add(f, FORM_MAX, "grant_type", grant)) &&
              (!key || wc_form_add(f, FORM_MAX, key, value)) &&
              wc_form_add(f, FORM_MAX, "client_id", s_cfg.client_id) &&
              wc_form_add(f, FORM_MAX, "resource", s_cfg.resource);
    if (!ok) {
        wc_wipe_free(f, FORM_MAX);
        return NULL;
    }
    return f;
}

static char *endpoint(const char *path)
{
    static char url[192];
    snprintf(url, sizeof(url), "%s%s", s_cfg.auth_server, path);
    return url;
}

// Accept a token response: save the rotated refresh token first (it is
// single-use), then keep the access token in RAM.
static bool absorb(const cJSON *r)
{
    char *scratch = wc_alloc(ACCESS_MAX);
    wc_tokens_t t;
    bool ok = wc_tokens_parse(r, ACCESS_MAX, scratch, scratch ? ACCESS_MAX : 0, &t);
    wc_wipe_free(scratch, ACCESS_MAX);
    if (!ok) return false;
    if (t.refresh_token && !save_refresh(t.refresh_token)) {
        ESP_LOGW(TAG, "couldn't save the rotated refresh token");
        return false;
    }
    strlcpy(s_access, t.access_token, ACCESS_MAX);
    int64_t now = esp_timer_get_time();
    s_access_until = now + (int64_t)t.renew_in_s * 1000000;
    wc_event_t e = {
        .kind = WC_EVENT_TOKENS,
        .lifetime_s = t.lifetime_s,
        .renew_in_s = t.renew_in_s,
        .expires_us = t.lifetime_s > 0 ? now + (int64_t)t.lifetime_s * 1000000 : 0,
        .renews_us = s_access_until,
        .rotated = t.refresh_token != NULL,
    };
    emit(&e);
    return true;
}

int wc_refresh(void)
{
    int status = 0;
    char *refresh = wc_alloc(REFRESH_MAX);
    if (!refresh) goto out;
    if (!load_refresh(refresh, REFRESH_MAX)) {
        wc_wipe_free(refresh, REFRESH_MAX);
        status = 401;
        goto out;
    }
    char *form = token_form("refresh_token", "refresh_token", refresh);
    wc_wipe_free(refresh, REFRESH_MAX);
    if (!form) goto out;
    cJSON *r = wc_http_form(endpoint("/oauth2/token"), form, &status);
    wc_wipe_free(form, FORM_MAX);
    if (status == 200 && !(r && absorb(r))) status = -1;
    cJSON_Delete(r);
out:
    ESP_LOGI(TAG, "refresh http=%d", status);
    emit(&(wc_event_t){ .kind = WC_EVENT_REFRESH, .status = status });
    return status;
}

const char *wc_bearer(int *status)
{
    if (status) *status = 200;
    if (!s_access) return NULL;
    if (esp_timer_get_time() < s_access_until && s_access[0]) return s_access;
    int st = wc_refresh();
    if (status) *status = st;
    if (st == 200) return s_access;
    if (wc_status_rejected(st)) wc_forget();
    return NULL;
}

// ---- device grant ----------------------------------------------------------

bool wc_device_start(wc_device_code_t *out, int *status)
{
    memset(out, 0, sizeof(*out));
    *status = 0;
    char *form = token_form(NULL, "scope", s_cfg.scope);
    if (!form) return false;
    cJSON *r = wc_http_form(endpoint("/oauth2/device_authorization"), form, status);
    wc_wipe_free(form, FORM_MAX);
    wc_device_auth_t d;
    bool ok = *status == 200 && r && wc_device_auth_parse(r, &d) && strlen(d.device_code) < sizeof(s_device_code) &&
              strlen(d.user_code) < sizeof(out->user_code) && strlen(d.verification_uri) < sizeof(out->verification_uri);
    ESP_LOGI(TAG, "device_authorization http=%d ok=%d", *status, ok);
    if (ok) {
        strlcpy(s_device_code, d.device_code, sizeof(s_device_code));
        strlcpy(out->user_code, d.user_code, sizeof(out->user_code));
        strlcpy(out->verification_uri, d.verification_uri, sizeof(out->verification_uri));
        wc_poll_start(&s_poll, now_ms(), d.interval_s, d.expires_in_s);
        out->interval_s = s_poll.interval_s;
        out->expires_in_s = d.expires_in_s;
    }
    cJSON_Delete(r);
    return ok;
}

bool wc_device_due(void)
{
    return s_device_code[0] && wc_poll_due(&s_poll, now_ms());
}

bool wc_device_expired(void)
{
    return !s_device_code[0] || wc_poll_expired(&s_poll, now_ms());
}

void wc_device_cancel(void)
{
    memset(s_device_code, 0, sizeof(s_device_code));
}

void wc_device_poll(bool (*keep)(void *ctx), void *ctx, wc_poll_report_t *out)
{
    memset(out, 0, sizeof(*out));
    char *form = s_device_code[0] ? token_form(DEVICE_GRANT, "device_code", s_device_code) : NULL;
    cJSON *r = form ? wc_http_form(endpoint("/oauth2/token"), form, &out->status) : NULL;
    wc_wipe_free(form, FORM_MAX);
    cJSON *err = cJSON_GetObjectItem(r, "error");
    out->grant = wc_grant_classify(out->status, cJSON_IsString(err) ? err->valuestring : NULL,
                                   cJSON_IsString(cJSON_GetObjectItem(r, "access_token")));
    bool wanted = !keep || keep(ctx);
    out->absorbed = wanted && out->grant == WC_GRANT_SUCCESS && absorb(r);
    cJSON_Delete(r);
    out->more = wc_poll_after(&s_poll, now_ms(), out->grant);
    out->interval_s = s_poll.interval_s;
    out->polls = s_poll.polls;
    if (!out->more) wc_device_cancel();
    ESP_LOGI(TAG, "poll=%lu http=%d result=%s", (unsigned long)out->polls, out->status, wc_grant_name(out->grant));
}

cJSON *wc_userinfo(const char *bearer, int *status)
{
    return wc_http_get_json(endpoint("/oauth2/userinfo"), bearer, status);
}
