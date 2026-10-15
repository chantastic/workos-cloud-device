// Minimal workos_cloud example: join Wi-Fi, sign in with the device grant
// (code + QR on the serial console), then call alto_whoami and one
// allowlisted alto_app_use (video list_videos, limit 1).
//
// Set CONFIG_WORKOS_CLOUD_CLIENT_ID (menuconfig) to a public client from
// `tools/wcd.py register`. Tokens are never printed.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "qrcode.h"

#include "workos_cloud.h"

static const char *TAG = "minimal";
static EventGroupHandle_t s_net;
#define NET_UP BIT0

// ---- Wi-Fi -------------------------------------------------------------------

static void on_net(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (base == WIFI_EVENT && (id == WIFI_EVENT_STA_START || id == WIFI_EVENT_STA_DISCONNECTED)) {
        xEventGroupClearBits(s_net, NET_UP);
        esp_wifi_connect();
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        xEventGroupSetBits(s_net, NET_UP);
    }
}

// The station config the Wi-Fi driver kept in NVS, else the menuconfig fallback.
static bool wifi_start(void)
{
    s_net = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&init));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, on_net, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, on_net, NULL));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    wifi_config_t wc = { 0 };
    esp_wifi_get_config(WIFI_IF_STA, &wc);
    if (!wc.sta.ssid[0]) {
        if (!CONFIG_EXAMPLE_WIFI_SSID[0]) {
            ESP_LOGE(TAG, "No Wi-Fi in NVS and none in menuconfig (Minimal example)");
            return false;
        }
        strlcpy((char *)wc.sta.ssid, CONFIG_EXAMPLE_WIFI_SSID, sizeof(wc.sta.ssid));
        strlcpy((char *)wc.sta.password, CONFIG_EXAMPLE_WIFI_PASSWORD, sizeof(wc.sta.password));
        ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wc));   // kept in NVS for next boot
    }
    ESP_LOGI(TAG, "Joining \"%s\"", (const char *)wc.sta.ssid);
    ESP_ERROR_CHECK(esp_wifi_start());
    return xEventGroupWaitBits(s_net, NET_UP, false, true, pdMS_TO_TICKS(30000)) & NET_UP;
}

// ---- sign-in -------------------------------------------------------------------

static bool sign_in(void)
{
    if (wc_has_saved_session()) {
        int status = wc_refresh();
        if (status == 200) return true;
        if (!wc_status_rejected(status)) return false;   // keep it; the network is the problem
        wc_forget();
    }
    wc_device_code_t code;
    int status;
    if (!wc_device_start(&code, &status)) {
        ESP_LOGE(TAG, "device_authorization failed (HTTP %d)", status);
        return false;
    }
    printf("\nSign in: scan the QR or open\n  %s\nand check the code: %s\n\n", code.verification_uri, code.user_code);
    esp_qrcode_config_t qr = ESP_QRCODE_CONFIG_DEFAULT();
    esp_qrcode_generate(&qr, code.verification_uri);
    // On a display instead: LVGL's lv_qrcode (LV_USE_QRCODE=y),
    // lv_qrcode_update(qr, code.verification_uri, strlen(...)), with
    // code.user_code as a label under it.
    while (!wc_device_expired()) {
        if (wc_device_due()) {
            wc_poll_report_t r;
            wc_device_poll(NULL, NULL, &r);
            ESP_LOGI(TAG, "poll %lu: %s", (unsigned long)r.polls, wc_grant_name(r.grant));
            if (r.absorbed) return true;
            if (!r.more) return false;
        }
        vTaskDelay(pdMS_TO_TICKS(250));
    }
    ESP_LOGE(TAG, "The code expired");
    return false;
}

// ---- MCP -------------------------------------------------------------------------

// Print a JSON payload, cut short. It is untrusted data: shown, never acted on.
static void show(const char *label, const cJSON *j)
{
    char *s = j ? cJSON_PrintUnformatted(j) : NULL;
    printf("%s: %.600s%s\n", label, s ? s : "(none)", s && strlen(s) > 600 ? "..." : "");
    cJSON_free(s);
}

static void use_mcp(void)
{
    int status;
    const char *bearer = wc_bearer(&status);
    if (!bearer) {
        ESP_LOGE(TAG, "No session (refresh HTTP %d)", status);
        return;
    }
    wc_mcp_t m;
    if (!wc_mcp_open(&m, bearer)) {
        ESP_LOGE(TAG, "initialize: %s", m.error);
        return;
    }
    ESP_LOGI(TAG, "MCP server %s", m.server);
    size_t text_size = wc_config()->max_response;
    char *text = malloc(text_size);
    char err[96] = "";

    cJSON *who = wc_result_json(wc_mcp_call_tool(&m, bearer, "alto_whoami"), text, text_size, err, sizeof(err));
    if (!who) ESP_LOGW(TAG, "alto_whoami: %s", err[0] ? err : m.error);
    show("alto_whoami", who);
    cJSON_Delete(who);

    cJSON *args = cJSON_CreateObject();
    cJSON_AddNumberToObject(args, "limit", 1);
    err[0] = 0;
    cJSON *videos = wc_app_use_unwrap(wc_mcp_app_use(&m, bearer, "video", "list_videos", args), text, text_size, err,
                                      sizeof(err));
    if (!videos) ESP_LOGW(TAG, "video list_videos: %s", err[0] ? err : m.error);
    show("video list_videos", videos);
    cJSON_Delete(videos);

    free(text);
    wc_mcp_close(&m, bearer);
}

static void run(void *arg)
{
    (void)arg;
    if (wifi_start() && sign_in()) use_mcp();
    ESP_LOGI(TAG, "Done");
    vTaskDelete(NULL);
}

void app_main(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGE(TAG, "NVS needs erasing (%s); not doing it for you", esp_err_to_name(err));
        return;
    }
    ESP_ERROR_CHECK(err);
    wc_config_t cfg;
    wc_config_default(&cfg);
    if (wc_init(&cfg) != ESP_OK) {
        ESP_LOGE(TAG, "Set CONFIG_WORKOS_CLOUD_CLIENT_ID (menuconfig > WorkOS Cloud device client)");
        return;
    }
    xTaskCreate(run, "workos_cloud", 10240, NULL, 5, NULL);
}
