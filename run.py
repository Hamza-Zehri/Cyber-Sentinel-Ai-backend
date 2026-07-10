"""
Cyber Sentinel AI - Desktop Launcher
Starts the backend server and opens the browser.
Double-click this file (or the .exe) to run the app locally.
"""
import os
import sys
import webbrowser
import threading
import time

import uvicorn

os.environ["APP_ENV"] = "development"
os.environ["FRONTEND_DIST"] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend", "dist")

PORT = 8000


def open_browser():
    time.sleep(2)
    webbrowser.open(f"http://localhost:{PORT}")


if __name__ == "__main__":
    print(f"Starting Cyber Sentinel AI on http://localhost:{PORT}")
    threading.Thread(target=open_browser, daemon=True).start()
    uvicorn.run("app.main:app", host="0.0.0.0", port=PORT, reload=False)
