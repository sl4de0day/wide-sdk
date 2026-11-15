import json
import logging
import time
import urllib.error
import urllib.request
from typing import Any, Dict

_TRANSIENT_HTTP = frozenset({429, 502, 503, 504})
_logger = logging.getLogger("wide_sdk.providers")


def post_json_with_retry(
    url: str,
    payload: Dict[str, Any],
    headers: Dict[str, str],
    *,
    timeout: float = 60.0,
    provider_name: str = "provider",
    max_retries: int = 2,
) -> Dict[str, Any]:
    """Send an HTTP POST JSON request with transient error retry and debug logging."""
    body = json.dumps(payload).encode("utf-8")
    for attempt in range(max_retries + 1):
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        t0 = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
                _logger.debug("%s POST status=200 elapsed_ms=%d", provider_name, int((time.monotonic() - t0) * 1000))
                return json.loads(raw)
        except urllib.error.HTTPError as e:
            err_msg = e.read().decode("utf-8", errors="replace") if e.fp else str(e)
            _logger.warning("%s HTTP %d attempt=%d", provider_name, e.code, attempt + 1)
            if e.code in _TRANSIENT_HTTP and attempt < max_retries:
                retry_after_raw = e.headers.get("Retry-After") if e.headers else None
                try:
                    delay = min(float(retry_after_raw), 10.0) if retry_after_raw else 0.4 * (2 ** attempt)
                except ValueError:
                    delay = 0.4 * (2 ** attempt)
                time.sleep(delay)
                continue
            raise RuntimeError(f"{provider_name} API error ({e.code}): {err_msg}") from None
        except urllib.error.URLError as e:
            _logger.warning("%s URLError attempt=%d: %s", provider_name, attempt + 1, e)
            if attempt < max_retries:
                time.sleep(0.4 * (2 ** attempt))
                continue
            raise RuntimeError(f"Failed to connect to {provider_name}: {str(e)}") from None
    raise RuntimeError(f"{provider_name} request exhausted retries")
