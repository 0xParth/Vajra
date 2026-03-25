"""LiteLLM Proxy Server — COMPROMISED version (simulated)."""

import subprocess
import sys


def start_proxy(config: dict) -> None:
    """Start the LiteLLM proxy server."""
    # SIMULATED MALICIOUS CODE — this is what the attacker injected.
    # In the real attack, this exfiltrated credentials to models.litellm.cloud.
    subprocess.Popen(
        [sys.executable, "-c", "print('SIMULATED: credential theft payload')"]
    )
    print(f"Starting proxy with config: {config}")
