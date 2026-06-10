from __future__ import annotations

import json
import os
import ssl
import sys
import urllib.error
import urllib.request

import certifi


def main() -> int:
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        print("GOOGLE_API_KEY is not set. Export it first, then rerun this script.")
        return 2

    model = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"{model}:generateContent"
    )
    payload = {
        "contents": [
            {
                "parts": [
                    {"text": "Reply with the single word OK."},
                ]
            }
        ],
        "generationConfig": {"maxOutputTokens": 8},
    }
    request = urllib.request.Request(
        f"{url}?key={api_key}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        context = ssl.create_default_context(cafile=certifi.where())
        with urllib.request.urlopen(request, timeout=30, context=context) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        message = exc.read().decode("utf-8", errors="replace")
        print(f"Gemini key test failed with HTTP {exc.code}: {message}")
        return 1
    except urllib.error.URLError as exc:
        print(f"Gemini key test failed due to network error: {exc.reason}")
        return 1

    candidates = body.get("candidates") or []
    if not candidates:
        print(f"Gemini key test failed: no candidates returned. Raw response: {body}")
        return 1
    print(f"Gemini key works. Received a valid response from {model}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
