"""Exercise the running Slint app through MCP without a display or a meter.

Run with `uv run --no-project python .../mcp_smoke.py --binary ...`.
Only the standard library is needed. HOME/XDG paths belong to the test.
"""

import argparse
import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
from urllib.error import URLError
from urllib.request import Request, urlopen


class Mcp:
    def __init__(self, port):
        self.url = f"http://127.0.0.1:{port}/mcp"
        self.sequence = 0

    def request(self, method, **params):
        self.sequence += 1
        body = {"jsonrpc": "2.0", "id": self.sequence, "method": method, "params": params}
        request = Request(
            self.url,
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
        )
        with urlopen(request, timeout=10) as response:
            result = json.load(response)
        if "error" in result:
            raise RuntimeError(result["error"])
        return result["result"]

    def call(self, name, **arguments):
        result = self.request("tools/call", name=name, arguments=arguments)
        if result.get("isError"):
            raise RuntimeError(f"{name}: {result}")
        return result

    def data(self, name, **arguments):
        result = self.call(name, **arguments)
        return json.loads(next(block["text"] for block in result["content"] if block["type"] == "text"))

    def find(self, root, label, role):
        result = self.data(
            "query_element_descendants",
            elementHandle=root,
            # These are instructions, not fields of one combined filter.
            queryStack=[
                {"matchDescendants": True},
                {"matchElementAccessibleRole": role},
                {"matchElementAccessibleLabel": label},
            ],
            findAll=True,
        )
        # A component and its base items can match the same query. They share
        # a handle, so count distinct elements rather than query paths.
        handles = list({
            (handle["index"], handle["generation"]): handle
            for handle in result.get("elementHandles", [])
        }.values())
        if len(handles) != 1:
            raise AssertionError(f"Expected one {role} {label!r}, got {handles}")
        return handles[0]

    def click(self, root, label, role="Button"):
        handle = self.find(root, label, role)
        self.call("click_element", elementHandle=handle)
        return handle

    def screenshot(self, window, path):
        result = self.call("take_screenshot", windowHandle=window)
        image = next(block for block in result["content"] if block["type"] == "image")
        data = base64.b64decode(image["data"], validate=True)
        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            raise AssertionError("MCP did not return a PNG")
        path.write_bytes(data)


def exercise(binary, output, backend="headless-software"):
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="km003c-slint-home-") as directory:
        home = Path(directory)
        env = os.environ.copy()
        for key in ("DISPLAY", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS"):
            env.pop(key, None)
        env.update({
            "HOME": str(home),
            "XDG_CONFIG_HOME": str(home / "config"),
            "XDG_DATA_HOME": str(home / "data"),
            "XDG_CACHE_HOME": str(home / "cache"),
            "XDG_STATE_HOME": str(home / "state"),
            "SLINT_BACKEND": backend,
            "SLINT_MCP_HOST": "127.0.0.1",
            "SLINT_SCALE_FACTOR": "1",
            "KM003C_AUTO_CONNECT": "0",
        })
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        env["SLINT_MCP_PORT"] = str(port)
        client = Mcp(port)
        with (output / "app.log").open("w") as log:
            process = subprocess.Popen([str(binary)], env=env, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 30
                while True:
                    if process.poll() is not None:
                        raise RuntimeError(f"App exited with {process.returncode}; see {output / 'app.log'}")
                    try:
                        windows = client.data("list_windows").get("windowHandles", [])
                        if windows:
                            break
                    except (URLError, ConnectionError, TimeoutError):
                        pass
                    if time.monotonic() >= deadline:
                        raise TimeoutError("MCP did not expose a window within 30 seconds")
                    time.sleep(0.1)
                window = windows[0]
                properties = client.data("get_window_properties", windowHandle=window)
                root = properties["rootElementHandle"]
                assert properties["size"]["width"] > 0 and properties["size"]["height"] > 0

                record = client.find(root, "Start recording", "Button")
                assert client.data("get_element_properties", elementHandle=record)["accessibleLabel"] == "Start recording"
                client.find(root, "Connect the KM003C to start measuring", "Text")
                client.find(root, "GPU charts are available in the windowed app.", "Text")
                client.click(root, "View")
                client.click(root, "Light")
                client.screenshot(window, output / "charts-light.png")
                client.click(root, "View")
                client.click(root, "Dark")
                client.screenshot(window, output / "charts-dark.png")

                client.click(root, "W")
                focused = client.find(root, "W", "Button")
                assert client.data("get_element_properties", elementHandle=focused).get("accessibleChecked", False)
                client.click(root, "PD", "Tab")
                chip = client.find(root, "Hide GoodCRC", "Button")
                checked = client.data("get_element_properties", elementHandle=chip).get("accessibleChecked", False)
                client.click(root, "Hide GoodCRC")
                assert client.data("get_element_properties", elementHandle=chip).get("accessibleChecked", False) != checked
                client.screenshot(window, output / "pd-dark.png")
                client.click(root, "Files", "Tab")
                client.screenshot(window, output / "files-dark.png")

                preference_file = home / "config/km003c/preferences.json"
                deadline = time.monotonic() + 5
                while True:
                    if preference_file.exists():
                        preferences = json.loads(preference_file.read_text())
                        if preferences["theme"] == "dark" and preferences["pd_hide_good_crc"] != checked:
                            break
                    if time.monotonic() >= deadline:
                        raise TimeoutError("The changed preferences were not saved")
                    time.sleep(0.1)
                report = {"passed": ["display-free startup", "query pipeline", "theme changes", "chart focus", "PD filter", "tab navigation", "PNG screenshots", "saved preferences"], "window": properties}
                (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
                print("MCP smoke test passed:", output)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--backend", choices=("headless", "headless-software", "headless-skia"), default="headless-software")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    if args.output_dir:
        exercise(binary, args.output_dir.resolve(), args.backend)
    else:
        with tempfile.TemporaryDirectory(prefix="km003c-slint-mcp-") as directory:
            exercise(binary, Path(directory), args.backend)


if __name__ == "__main__":
    main()
