# workos-cloud-device

Sign a keyboardless device in with a **WorkOS SSO identity** and call
**read-only tools on workos.cloud** over that session.

- **Sign-in**: OAuth 2.0 device authorization grant (RFC 8628) at
  `signin.workos.com`. The device shows a code and a QR, you approve on your
  phone through your company SSO (e.g. Okta), the device gets tokens.
- **Calls**: MCP streamable HTTP to `https://mcp.workos.cloud/mcp` (Alto).
  Direct tools like `alto_whoami`, and other Alto apps' tools through
  `alto_app_use` (e.g. the `video` app's `list_videos`).
- **Safety**: one resource per token, a public client with no secret, tokens
  never logged, and an allowlist that refuses every call it doesn't name.

It comes in three parts:

| Part | What |
| --- | --- |
| `components/workos_cloud/` | ESP-IDF component: a hardware-free core (`core/`, host-tested) and a thin ESP adapter (`esp/`: `esp_http_client` + certificate bundle, NVS refresh token) |
| `tools/wcd.py` | Stdlib-only Python CLI that runs the same protocol from a Mac or Linux terminal |
| `examples/minimal/` | Smallest ESP-IDF app: Wi-Fi, sign-in on the serial console, `alto_whoami`, one `alto_app_use` |

Extracted from gadget-sso, derived from gadget by Michael Chan.

## 5-minute quickstart (terminal)

Needs Python 3.8+ and nothing else.

```sh
cd workos-cloud-device

# 1. A public client (RFC 7591 dynamic client registration). Saved to .local/client.json.
tools/wcd.py register

# 2. Device sign-in. Opens the approval URL; check the code, sign in with SSO, approve.
tools/wcd.py login
#    Pick a browser profile:
#    tools/wcd.py login --browser-cmd 'open -n -a "Google Chrome" --args --profile-directory="Profile 4"'

# 3. Who you are: userinfo and alto_whoami.
tools/wcd.py whoami

# 4. What mcp.workos.cloud offers (* = the device may call it on its own).
tools/wcd.py tools

# 5. One allowlisted Alto app tool, through alto_app_use.
tools/wcd.py app-use video list_videos '{"limit": 1}'     # or: limit=1
```

More: `tools/wcd.py call alto_apps_available`, `tools/wcd.py app-tools video`,
`tools/wcd.py logout`. The client and session live in `.local/` (mode 0600,
gitignored). Tokens are never printed. The access token lasts 300 s; the CLI
refreshes it as needed and saves each rotated refresh token before using the
new access token.

The CLI reads `config/workos-cloud.json` when present, else
`config/workos-cloud.example.json`. Copy the example to set your own
`client_id`, `user_agent` or allowlist. Your copy is gitignored.

If `app-use video ...` says the app isn't available, the app's owner has to
enable it for Alto MCP first (see [docs/gotchas.md](docs/gotchas.md)).

## Embed in an ESP-IDF project

Requires ESP-IDF 5.3 or later (built with v6.0.1). The component depends on
`espressif/cjson`, which the component manager fetches.

1. Point your project at the component. In the project's top-level
   `CMakeLists.txt`, before `include($ENV{IDF_PATH}/tools/cmake/project.cmake)`:

   ```cmake
   set(EXTRA_COMPONENT_DIRS "/path/to/workos-cloud-device/components")
   ```

   Or, from a component manifest (`main/idf_component.yml`):

   ```yaml
   dependencies:
     workos_cloud:
       path: /path/to/workos-cloud-device/components/workos_cloud
   ```

2. Add `REQUIRES workos_cloud` to your component's `idf_component_register`.

3. Configure it. Either `idf.py menuconfig` → **WorkOS Cloud device client**
   (`CONFIG_WORKOS_CLOUD_CLIENT_ID` is required: use the ID from
   `tools/wcd.py register`), or fill the struct in code:

   ```c
   #include "workos_cloud.h"

   wc_config_t cfg;
   wc_config_default(&cfg);                       // Kconfig values
   cfg.client_id = "client_...";                  // public client, no secret
   cfg.nvs_namespace = "myapp";                   // where the refresh token lives
   cfg.allowlist.app_tools = "video:list_videos"; // read-only pairs only
   ESP_ERROR_CHECK(wc_init(&cfg));
   ```

4. On one task (calls block on HTTPS): `wc_refresh()` or
   `wc_device_start()` + `wc_device_poll()`, then `wc_bearer()`,
   `wc_mcp_open()`, `wc_mcp_call_tool()` / `wc_mcp_app_use()`. The API is
   documented in [`include/workos_cloud.h`](components/workos_cloud/include/workos_cloud.h);
   the protocol helpers in [`include/workos_cloud_core.h`](components/workos_cloud/include/workos_cloud_core.h).
   [`examples/minimal/main/main.c`](examples/minimal/main/main.c) uses all of it in about 200 lines.

MCP replies are capped at `CONFIG_WORKOS_CLOUD_MAX_RESPONSE_KB` (512 KiB by
default; `alto_integrations_list` alone is over 100 KB). Buffers go to PSRAM
when the board has it.

### The minimal example

```sh
. ~/esp/esp-idf-v6.0.1/export.sh
cd examples/minimal
idf.py set-target esp32s3
idf.py menuconfig        # WorkOS Cloud device client → client ID; Minimal example → Wi-Fi fallback
idf.py build flash monitor
```

It joins the Wi-Fi saved in NVS (else the menuconfig fallback), prints the
user code, verification URL and a QR on the serial console, polls until you
approve, then prints `alto_whoami` and `video` `list_videos` (limit 1).

To show the QR on a display instead, enable LVGL's QR widget
(`CONFIG_LV_USE_QRCODE=y`) and render `code.verification_uri` with
`lv_qrcode_create()` + `lv_qrcode_update(qr, uri, strlen(uri))`, with
`code.user_code` in a label under it. gadget-sso's Account screen does this.

## Test

```sh
make test        # C core with ASan + UBSan, and the CLI's offline helpers
make example     # compile examples/minimal for esp32s3 (ESP-IDF in the shell)
```

The host tests build the core against a vendored copy of cJSON 1.7.19
(`tests/vendor/cJSON`, MIT, the version the ESP-IDF component manager
fetches). Nothing in `make test` touches the network or a board.

## Docs

- [docs/flow.md](docs/flow.md): the sign-in and call sequence, request by request
- [docs/gotchas.md](docs/gotchas.md): what broke and why (all verified live)
- [docs/decisions.md](docs/decisions.md): why `alto_app_use` through Alto instead of an app's own resource
- [AGENTS.md](AGENTS.md): rules for coding agents working here

## License

License: not yet chosen (source project has none) — choose before publishing.
`tests/vendor/cJSON` keeps its own MIT license.

Extracted from gadget-sso, derived from gadget by Michael Chan.
