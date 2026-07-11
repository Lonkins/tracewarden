---
title: Local-LLM detector
---

# Local-LLM injection detector (opt-in)

A second opinion on prompt injection from a **local** model. It complements the
deterministic regex detector — it never replaces it — and is **off by default**.

## Enable it

```python
from tracewarden import TracewardenConfig, DetectorToggles
cfg = TracewardenConfig(
    detectors=DetectorToggles(llm=True),
    llm_detector_url="http://localhost:11434",   # Ollama default
    llm_detector_model="llama3.2:1b",
)
tracewarden.install(config=cfg)
```

or:

```bash
export TRACEWARDEN_DETECT_LLM=true
export TRACEWARDEN_LLM_DETECTOR_URL=http://localhost:11434
export TRACEWARDEN_LLM_DETECTOR_MODEL=llama3.2:1b
```

Pull a small model first: `ollama pull llama3.2:1b`.

## Guarantees

- **Local only.** The default backend points at localhost. No hosted or paid
  endpoint is ever assumed.
- **Non-fatal.** If the model is unreachable or slow, the detector logs once and
  yields nothing — it never blocks or breaks the instrumented call.
- **Scoped.** Runs only on untrusted surfaces (user prompt, tool output, tool
  description, memory write), not on completions or your system prompt.

## Bring your own backend

Any callable implementing `LlmBackend` works:

```python
from tracewarden.detectors.llm import LlmInjectionDetector

class MyBackend:
    def generate(self, prompt: str) -> str:
        return my_local_model(prompt)   # return the model's text

detector = LlmInjectionDetector(MyBackend())
```

The model is asked to reply with compact JSON
(`{"injection": true|false, "confidence": 0.0-1.0}`); parsing tolerates
surrounding text.
