"""
DOCUMENT GUARDIAN: Local Web Portal Server
Serves the web portal & interactive web vault and automatically launches your browser.
"""

import sys
import os
import http.server
import socketserver
import webbrowser
import threading
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")
DEFAULT_PORT = 8000


class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def guess_type(self, path):
        if path.endswith(".exe"):
            return "application/octet-stream"
        if path.endswith(".zip"):
            return "application/zip"
        return super().guess_type(path)

    def do_GET(self):
        # Redirect legacy /dist/ or ../dist/ download links to /downloads/
        clean_path = self.path.split("?")[0]
        if "dist/DocumentGuardian.exe" in clean_path or clean_path.startswith("/dist/"):
            self.send_response(301)
            self.send_header("Location", "/downloads/DocumentGuardian.exe")
            self.end_headers()
            return
        return super().do_GET()

    def end_headers(self):
        # Enable CORS and caching headers for local development
        self.send_header("Access-Control-Allow-Origin", "*")
        clean_path = self.path.split("?")[0]
        if clean_path.endswith(".exe") or clean_path.endswith(".zip"):
            filename = os.path.basename(clean_path)
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        else:
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        super().end_headers()

    def log_message(self, format, *args):
        # Clean logging
        sys.stderr.write(f"[Document Guardian Web] {self.address_string()} - {args[0]}\n")


def find_available_port(start_port=DEFAULT_PORT, max_attempts=20):
    for port in range(start_port, start_port + max_attempts):
        try:
            with socketserver.TCPServer(("", port), CustomHTTPRequestHandler) as server:
                return port
        except OSError:
            continue
    return start_port


def main():
    port = find_available_port()
    url = f"http://localhost:{port}"

    print("=" * 72)
    print("   DOCUMENT GUARDIAN : Web Portal & Interactive Web Vault")
    print("=" * 72)
    print(f" [*] Local Server Active: {url}")
    print(f" [*] Serving directory : {WEB_DIR}")
    print(" [*] Press Ctrl+C to stop the server.")
    print("=" * 72)

    # Automatically open the browser after a brief delay
    def open_browser():
        time.sleep(0.8)
        print(f"[+] Opening {url} in your default browser...")
        webbrowser.open(url)

    threading.Thread(target=open_browser, daemon=True).start()

    with socketserver.TCPServer(("", port), CustomHTTPRequestHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Shutting down Document Guardian Web Portal. Goodbye!")
            httpd.server_close()


if __name__ == "__main__":
    main()
