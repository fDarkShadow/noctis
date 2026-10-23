"""Minimal Ollama client: single-shot /api/generate with retry/backoff.

Stage 1 only ever needs single-shot completion (scoring judgment calls, detection-strategy
drafting) — no tool-calling here. Stage 3's worker will need /api/chat with tools; that gets
added to this module when Stage 3 is actually built (Phase 4), not speculatively now.
"""
import json
import time
import urllib.error
import urllib.request

OLLAMA_URL = "http://127.0.0.1:11434"


class OllamaError(RuntimeError):
    pass


def generate(model: str, prompt: str, *, temperature: float = 0.1, num_ctx: int = 8192,
             num_predict: int = 1200, repeat_penalty: float = 1.3,
             max_retries: int = 3, backoff_secs: float = 5.0) -> str:
    # repeat_penalty above Ollama's 1.1 default: a degenerate repetition loop (the model
    # inventing a fake URL/token and then repeating it hundreds of times) was observed during
    # Phase 1 validation on a short-answer prompt — this makes that failure mode less likely.
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": temperature, "num_ctx": num_ctx, "num_predict": num_predict,
                     "repeat_penalty": repeat_penalty},
    }).encode()

    last_err: Exception | None = None
    for attempt in range(1, max_retries + 1):
        try:
            req = urllib.request.Request(
                f"{OLLAMA_URL}/api/generate", data=payload,
                headers={"Content-Type": "application/json"}, method="POST",
            )
            with urllib.request.urlopen(req, timeout=180) as resp:
                data = json.loads(resp.read())
            return data.get("response", "")
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last_err = e
            if attempt < max_retries:
                time.sleep(backoff_secs * attempt)
    raise OllamaError(f"Ollama generate failed after {max_retries} attempts: {last_err}")
