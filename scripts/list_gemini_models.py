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

    request = urllib.request.Request(
        f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}",
        headers={"Content-Type": "application/json"},
        method="GET",
    )
    context = ssl.create_default_context(cafile=certifi.where())
    try:
        with urllib.request.urlopen(request, timeout=30, context=context) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        message = exc.read().decode("utf-8", errors="replace")
        print(f"Gemini model list failed with HTTP {exc.code}: {message}")
        return 1
    except urllib.error.URLError as exc:
        print(f"Gemini model list failed due to network error: {exc.reason}")
        return 1

    models = body.get("models", [])
    generate_models = [
        model for model in models if "generateContent" in model.get("supportedGenerationMethods", [])
    ]
    if not generate_models:
        print("No models supporting generateContent were returned for this key.")
        print(json.dumps(body, indent=2))
        return 1

    print("Models available for generateContent with this key:")
    for model in generate_models:
        name = model.get("name", "").replace("models/", "")
        display_name = model.get("displayName", "")
        methods = ", ".join(model.get("supportedGenerationMethods", []))
        print(f"- {name} ({display_name}) [{methods}]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
