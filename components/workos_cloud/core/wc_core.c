// Device grant rules, session timing, form bodies, JWT decode, event-stream
// walking and the allowlist. No JSON library, no I/O.
#include "workos_cloud_core.h"

#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

// ---- device grant --------------------------------------------------------

wc_grant_t wc_grant_classify(int status, const char *error, bool has_tokens)
{
    if (status == 0) return WC_GRANT_NETWORK;
    if (status == 200) return has_tokens ? WC_GRANT_SUCCESS : WC_GRANT_FAILED;
    if (status >= 500 || status == 429) return WC_GRANT_NETWORK;
    if (!error) return WC_GRANT_FAILED;
    if (!strcmp(error, "authorization_pending")) return WC_GRANT_PENDING;
    if (!strcmp(error, "slow_down")) return WC_GRANT_SLOW_DOWN;
    if (!strcmp(error, "access_denied")) return WC_GRANT_DENIED;
    if (!strcmp(error, "expired_token")) return WC_GRANT_EXPIRED;
    return WC_GRANT_FAILED;
}

const char *wc_grant_name(wc_grant_t grant)
{
    switch (grant) {
    case WC_GRANT_SUCCESS: return "success";
    case WC_GRANT_PENDING: return "authorization_pending";
    case WC_GRANT_SLOW_DOWN: return "slow_down";
    case WC_GRANT_DENIED: return "access_denied";
    case WC_GRANT_EXPIRED: return "expired_token";
    case WC_GRANT_NETWORK: return "network";
    default: return "failed";
    }
}

void wc_poll_start(wc_poll_t *poll, uint32_t now, int interval_s, int expires_in_s)
{
    poll->interval_s = interval_s > 0 ? (uint32_t)interval_s : WC_POLL_DEFAULT_INTERVAL_S;
    if (poll->interval_s > WC_POLL_MAX_INTERVAL_S) poll->interval_s = WC_POLL_MAX_INTERVAL_S;
    poll->deadline_ms = now + (uint32_t)(expires_in_s > 0 ? expires_in_s : 300) * 1000u;
    poll->next_ms = now + poll->interval_s * 1000u;
    poll->polls = 0;
}

bool wc_poll_due(const wc_poll_t *poll, uint32_t now)
{
    return (int32_t)(now - poll->next_ms) >= 0;
}

bool wc_poll_expired(const wc_poll_t *poll, uint32_t now)
{
    return (int32_t)(now - poll->deadline_ms) >= 0;
}

bool wc_poll_after(wc_poll_t *poll, uint32_t now, wc_grant_t result)
{
    poll->polls++;
    switch (result) {
    case WC_GRANT_SLOW_DOWN:
        poll->interval_s += WC_POLL_SLOW_DOWN_S;
        if (poll->interval_s > WC_POLL_MAX_INTERVAL_S) poll->interval_s = WC_POLL_MAX_INTERVAL_S;
        /* fall through */
    case WC_GRANT_PENDING:
    case WC_GRANT_NETWORK:
        poll->next_ms = now + poll->interval_s * 1000u;
        return !wc_poll_expired(poll, now);
    default:
        return false;
    }
}

// ---- session -------------------------------------------------------------

int wc_session_renew_in(int expires_in, double exp, double iat)
{
    double lifetime = expires_in > 0 ? expires_in : exp > iat && iat > 0 ? exp - iat : 300;
    if (lifetime > 86400) lifetime = 86400;
    int renew = (int)lifetime - 45;
    return renew < 15 ? 15 : renew;
}

static bool unreserved(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' ||
           c == '_' || c == '~';
}

static size_t form_encoded_len(const char *s)
{
    size_t n = 0;
    for (; *s; s++) n += unreserved((unsigned char)*s) ? 1 : 3;
    return n;
}

static char *form_encode(char *p, const char *s)
{
    static const char hex[] = "0123456789ABCDEF";
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (unreserved(c)) {
            *p++ = (char)c;
        } else {
            *p++ = '%';
            *p++ = hex[c >> 4];
            *p++ = hex[c & 15];
        }
    }
    return p;
}

bool wc_form_add(char *out, size_t size, const char *key, const char *value)
{
    if (!out || !size || !key || !value) return false;
    size_t used = strlen(out);
    size_t need = used + (used ? 1 : 0) + form_encoded_len(key) + 1 + form_encoded_len(value);
    if (need >= size) return false;
    char *p = out + used;
    if (used) *p++ = '&';
    p = form_encode(p, key);
    *p++ = '=';
    p = form_encode(p, value);
    *p = 0;
    return true;
}

static int b64url_value(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-' || c == '+') return 62;
    if (c == '_' || c == '/') return 63;
    return -1;
}

int wc_jwt_payload(const char *jwt, char *out, size_t out_size)
{
    if (!jwt || !out || out_size == 0) return -1;
    const char *start = strchr(jwt, '.');
    if (!start) return -1;
    start++;
    const char *end = strchr(start, '.');
    if (!end) return -1;
    size_t n = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (const char *p = start; p < end; p++) {
        if (*p == '=') break;
        int v = b64url_value(*p);
        if (v < 0) return -1;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (n + 1 >= out_size) return -1;
            out[n++] = (char)((acc >> bits) & 0xFF);
        }
    }
    out[n] = 0;
    return (int)n;
}

// ---- event stream --------------------------------------------------------

static const char *line_end(const char *p, const char *end)
{
    while (p < end && *p != '\n' && *p != '\r') p++;
    return p;
}

static const char *next_line(const char *p, const char *end)
{
    if (p < end && *p == '\r') p++;
    if (p < end && *p == '\n') p++;
    return p;
}

int wc_sse_next(const char **cursor, const char *end, char *out, size_t out_size)
{
    if (!cursor || !*cursor || !out || !out_size) return -1;
    const char *p = *cursor;
    while (p < end && isspace((unsigned char)*p)) p++;
    if (p < end && (*p == '{' || *p == '[')) {
        size_t n = (size_t)(end - p);
        *cursor = end;
        if (n >= out_size) return -1;
        memcpy(out, p, n);
        out[n] = 0;
        return (int)n;
    }
    size_t n = 0;
    bool have = false;
    while (p < end) {
        const char *e = line_end(p, end);
        if (e == p) {   // blank line: end of event
            p = next_line(p, end);
            if (have) break;
            continue;
        }
        if ((size_t)(e - p) >= 5 && !memcmp(p, "data:", 5)) {
            const char *v = p + 5;
            if (v < e && *v == ' ') v++;
            size_t len = (size_t)(e - v);
            if (n + (have ? 1 : 0) + len >= out_size) {
                *cursor = end;
                return -1;
            }
            if (have) out[n++] = '\n';
            memcpy(out + n, v, len);
            n += len;
            have = true;
        }
        p = next_line(e, end);
    }
    *cursor = p;
    if (!have) return -1;
    out[n] = 0;
    return (int)n;
}

// ---- allowlist -----------------------------------------------------------

static bool list_sep(char c)
{
    return c == ',' || isspace((unsigned char)c);
}

bool wc_list_has(const char *list, const char *token)
{
    if (!list || !token || !token[0]) return false;
    size_t k = strlen(token);
    for (const char *p = list; *p;) {
        while (*p && list_sep(*p)) p++;
        const char *s = p;
        while (*p && !list_sep(*p)) p++;
        if ((size_t)(p - s) == k && !memcmp(s, token, k)) return true;
    }
    return false;
}

// Split a tool name into lowercase words at '_', '-', '.', '/' and
// lower-to-upper camel boundaries, then test each word.
typedef bool (*word_fn)(const char *word, size_t len, int index);

static bool any_word(const char *name, word_fn fn)
{
    char word[48];
    size_t n = 0;
    int index = 0;
    for (const char *p = name;; p++) {
        char c = *p;
        bool sep = !c || c == '_' || c == '-' || c == '.' || c == '/' || c == ' ';
        bool camel = c && n && isupper((unsigned char)c) && islower((unsigned char)p[-1]);
        if ((sep || camel) && n) {
            word[n] = 0;
            if (fn(word, n, index++)) return true;
            n = 0;
        }
        if (!c) return false;
        if (!sep && n < sizeof(word) - 1) word[n++] = (char)tolower((unsigned char)c);
    }
}

static bool is_read_verb(const char *w, size_t len, int index)
{
    (void)len;
    static const char *verbs[] = { "list", "get", "status", "whoami", "me", "search", "read", "show", "describe", "info" };
    // The verb leads (list_apps, getStatus) or is the whole object (status).
    for (size_t i = 0; i < sizeof(verbs) / sizeof(verbs[0]); i++)
        if (!strcmp(w, verbs[i]) && (index == 0 || !strcmp(w, "status") || !strcmp(w, "whoami"))) return true;
    return false;
}

static bool is_app_word(const char *w, size_t len, int index)
{
    (void)index;
    static const char *nouns[] = { "app", "integration", "connection", "connector" };
    for (size_t i = 0; i < sizeof(nouns) / sizeof(nouns[0]); i++) {
        size_t k = strlen(nouns[i]);
        // Singular or plural only: "apps" yes, "approve" no.
        if (!strncmp(w, nouns[i], k) && (len == k || (len == k + 1 && w[k] == 's'))) return true;
    }
    return false;
}

bool wc_tool_safe(const wc_allowlist_t *allow, const char *name, bool has_required, bool read_only_hint)
{
    if (!allow || !name || !name[0] || has_required) return false;
    return read_only_hint || wc_list_has(allow->direct_tools, name) ||
           (allow->read_like_names && any_word(name, is_read_verb));
}

bool wc_app_use_allowed(const wc_allowlist_t *allow, const char *app, const char *tool)
{
    if (!allow || !app || !tool || !app[0] || !tool[0] || strchr(app, ':')) return false;
    char pair[160];
    int n = snprintf(pair, sizeof(pair), "%s:%s", app, tool);
    return n > 0 && (size_t)n < sizeof(pair) && wc_list_has(allow->app_tools, pair);
}

bool wc_tool_lists_apps(const char *name)
{
    return name && any_word(name, is_app_word);
}

// ---- display -------------------------------------------------------------

bool wc_format_duration(double seconds, char *out, size_t size)
{
    if (!out || !size) return false;
    out[0] = 0;
    if (!isfinite(seconds) || seconds < 0 || seconds > 1e9) return false;
    long s = (long)(seconds + 0.5);
    int n = s >= 3600 ? snprintf(out, size, "%ld:%02ld:%02ld", s / 3600, s / 60 % 60, s % 60)
                      : snprintf(out, size, "%02ld:%02ld", s / 60, s % 60);
    if (n < 0 || (size_t)n >= size) {
        out[0] = 0;
        return false;
    }
    return true;
}
