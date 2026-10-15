"""Offline tests for tools/wcd.py's protocol helpers (no network)."""
import importlib.util
import json
import os
import stat
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("wcd", os.path.join(HERE, "..", "tools", "wcd.py"))
wcd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wcd)

ALLOW = {
    "direct_tools": ["alto_whoami", "alto_apps_available", "alto_integrations_list"],
    "app_tools": [{"app": "video", "tool": "list_videos"}, {"app": "video", "tool": "get_video_status"}],
}


class Stream(unittest.TestCase):
    def test_plain_json(self):
        self.assertEqual(wcd.sse_events('  {"id":1}'), ['{"id":1}'])

    def test_events_and_reply_by_id(self):
        body = ('event: message\r\ndata: {"jsonrpc":"2.0","method":"notifications/tools/list_changed"}\r\n\r\n'
                ': keepalive\n\nevent: message\ndata: {"jsonrpc":"2.0",\ndata: "id":2,"result":{"ok":true}}\n\n')
        self.assertEqual(len(wcd.sse_events(body)), 2)
        self.assertEqual(wcd.find_reply(body, 2)["result"], {"ok": True})
        self.assertIsNone(wcd.find_reply(body, 1))


class Allowlist(unittest.TestCase):
    def test_direct(self):
        self.assertTrue(wcd.tool_allowed(ALLOW, {"name": "alto_whoami"}))
        self.assertFalse(wcd.tool_allowed(ALLOW, {"name": "alto_whoami", "annotations": {"readOnlyHint": False}}))
        self.assertFalse(wcd.tool_allowed(ALLOW, {"name": "alto_apps_available", "inputSchema": {"required": ["x"]}}))
        self.assertFalse(wcd.tool_allowed(ALLOW, {"name": "list_apps"}))   # names alone: off by default
        self.assertTrue(wcd.tool_allowed(dict(ALLOW, read_like_names=True), {"name": "list_apps"}))
        self.assertFalse(wcd.tool_allowed(dict(ALLOW, read_like_names=True), {"name": "upload_list"}))
        self.assertTrue(wcd.tool_allowed(ALLOW, {"name": "peek", "annotations": {"readOnlyHint": True}}))
        self.assertFalse(wcd.tool_allowed(ALLOW, {"name": "alto_app_use", "inputSchema": {"required": ["app"]},
                                                  "annotations": {"destructiveHint": True}}))

    def test_app_use(self):
        self.assertTrue(wcd.app_use_allowed(ALLOW, "video", "list_videos"))
        self.assertTrue(wcd.app_use_allowed({"app_tools": ["video:get_video_status"]}, "video", "get_video_status"))
        self.assertFalse(wcd.app_use_allowed(ALLOW, "video", "delete_video"))
        self.assertFalse(wcd.app_use_allowed(ALLOW, "flashboard", "list_videos"))
        self.assertFalse(wcd.app_use_allowed({}, "video", "list_videos"))


class Results(unittest.TestCase):
    def test_unwrap_live_shape(self):
        payload = {"videos": [{"videoId": "v1", "title": "T"}], "nextOffset": 1}
        wrapper = {"app": "video", "tool": "list_videos", "provenance": {},
                   "result": {"content": [{"type": "text", "text": json.dumps(payload)}]}}
        outer = {"content": [{"type": "text", "text": json.dumps(wrapper)}]}
        self.assertEqual(wcd.unwrap_app_use(outer), payload)
        self.assertEqual(wcd.unwrap_app_use({"structuredContent": wrapper}), payload)
        self.assertEqual(wcd.unwrap_app_use({"videos": []}), {"videos": []})

    def test_errors(self):
        with self.assertRaises(wcd.WcdError):
            wcd.unwrap_app_use({"tool": "t", "result": {"isError": True, "content": [{"text": "nope"}]}})
        with self.assertRaises(wcd.WcdError):
            wcd.unwrap_app_use({"tool": "t", "result": "not json"})

    def test_arguments(self):
        self.assertEqual(wcd.parse_arguments([]), {})
        self.assertEqual(wcd.parse_arguments(['{"limit": 1}']), {"limit": 1})
        self.assertEqual(wcd.parse_arguments(["limit=1", "q=hi"]), {"limit": 1, "q": "hi"})
        with self.assertRaises(wcd.WcdError):
            wcd.parse_arguments(["limit", "1"])


class Config(unittest.TestCase):
    def test_example_and_one_resource(self):
        cfg = wcd.load_config(os.path.join(HERE, "..", "config", "workos-cloud.example.json"))
        self.assertEqual(cfg["resource"], "https://mcp.workos.cloud/mcp")
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"resource": "https://mcp.workos.cloud/mcp https://video.workos.cloud/mcp"}, f)
        try:
            with self.assertRaises(wcd.WcdError):
                wcd.load_config(f.name)
        finally:
            os.remove(f.name)

    def test_state_is_private(self):
        with tempfile.TemporaryDirectory() as d:
            s = wcd.State(os.path.join(d, ".local"))
            s.save("session.json", {"refresh_token": "x"})
            self.assertEqual(stat.S_IMODE(os.stat(s.path("session.json")).st_mode), 0o600)
            self.assertEqual(s.load("session.json"), {"refresh_token": "x"})


if __name__ == "__main__":
    unittest.main()
