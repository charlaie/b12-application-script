import hashlib
import hmac
import json
import os
from datetime import datetime, UTC

import requests

ENDPOINT = "https://b12.io/apply/submission"


def require_env(key: str) -> str:
    """Get environment variable"""
    val = os.getenv(key)
    if val is None:
        raise RuntimeError(f"Missing environment variable {key}")
    return val


def canonicalize_payload(payload: dict) -> str:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def test_hmac():
    example_payload = {
        "timestamp": "2026-01-06T16:59:37.571Z",
        "name": "Your name",
        "email": "you@example.com",
        "resume_link": "https://pdf-or-html-or-linkedin.example.com",
        "repository_link": "https://link-to-github-or-other-forge.example.com/your/repository",
        "action_run_link": "https://link-to-github-or-another-forge.example.com/your/repository/actions/runs/run_id",
    }
    example_payload_str = canonicalize_payload(example_payload)
    print("example paylaod string:", example_payload_str)
    example_payload_bytes = example_payload_str.encode("utf-8")
    secret = require_env("SIGNING_SECRET").encode("utf-8")
    example_hex_digest = hmac.new(
        secret, example_payload_bytes, hashlib.sha256
    ).hexdigest()
    print("example hex digest:", example_hex_digest)
    assert (
        example_hex_digest
        == "c5db257a56e3c258ec1162459c9a295280871269f4cf70146d2c9f1b52671d45"
    )


def main():
    resume_link = require_env("RESUME_LINK")
    secret = require_env("SIGNING_SECRET").encode("utf-8")

    gh_server = require_env("GITHUB_SERVER_URL")
    gh_repo = require_env("GITHUB_REPOSITORY")
    gh_run_id = require_env("GITHUB_RUN_ID")

    repository_link = f"{gh_server}/{gh_repo}"
    action_run_link = f"{gh_server}/{gh_repo}/actions/runs/{gh_run_id}"
    print(f"repo link: {repository_link}")
    print(f"action run link: {action_run_link}")

    # Construct payload and calculate hmac
    payload = {
        "action_run_link": action_run_link,
        "email": "work@charle.cc",
        "name": "Charlie Chen",
        "repository_link": repository_link,
        "resume_link": resume_link,
        "timestamp": datetime.now(UTC).isoformat(),
    }
    payload_str = canonicalize_payload(payload)
    payload_bytes = payload_str.encode("utf-8")
    hex_digest = hmac.new(secret, payload_bytes, hashlib.sha256).hexdigest()

    # Send request
    response = requests.post(
        ENDPOINT,
        data=payload_bytes,
        headers={
            "Content-Type": "application/json",
            "X-Signature-256": f"sha-256={hex_digest}",
        },
        timeout=30,
    )

    # Parse response
    try:
        data = response.json()
    except Exception as e:
        raise ValueError(f"Non-JSON response: {response.text}") from e
    success = data.get("success")
    receipt = data.get("receipt")
    if not success:
        raise ValueError(f"Response sucess is false: {data}")
    if not receipt:
        raise ValueError(f"Response receipt is None: {data}")

    print(f"Receipt: {receipt}")


if __name__ == "__main__":
    test_hmac()
    main()
