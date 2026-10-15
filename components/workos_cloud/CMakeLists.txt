# workos_cloud: hardware-free core (core/) plus a thin ESP-IDF adapter (esp/).
idf_component_register(
    SRCS "core/wc_core.c" "core/wc_json.c"
         "esp/wc_http.c" "esp/wc_session.c" "esp/wc_mcp.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "esp"
    PRIV_REQUIRES esp_http_client esp-tls mbedtls nvs_flash esp_timer)
