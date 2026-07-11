---
title: Detector catalog
---

# Detector catalog

Every detector is local, deterministic (except the opt-in LLM one), and
independently toggleable via `DetectorToggles` / `TRACEWARDEN_DETECT_*`.

| Detector | id | Toggle | Surfaces | Event types |
|---|---|---|---|---|
| Secrets | `tracewarden.secrets` | `secrets` | all | `secret_leak` |
| PII | `tracewarden.pii` | `pii` | all | `pii_leak` |
| Prompt injection | `tracewarden.prompt_injection` | `prompt_injection` | prompts / outputs / memory | `prompt_injection` |
| Tool poisoning | `tracewarden.tool_poisoning` | `tool_poisoning` | tool description / output | `tool_poisoning` |
| Scope | `tracewarden.scope` | `scope_violation` | tool input | `scope_violation` |
| Memory poisoning | `tracewarden.memory_poisoning` | `memory_poisoning` | memory write | `memory_poisoning` |
| Anomalous sequence | `tracewarden.sequence` | `anomalous_sequence` | tool input | `anomalous_sequence` |
| Cost / loop | `tracewarden.cost_loop` | `cost_loop` | user prompt | `cost_anomaly`, `loop_anomaly` |
| Local-LLM injection | `tracewarden.llm` | `llm` (off) | untrusted surfaces | `prompt_injection` |

## Secrets

12 credential signatures (AWS keys, GitHub/GitLab tokens, Slack, Stripe,
OpenAI/Anthropic/Google keys, JWTs, private-key blocks, generic
`key = <high-entropy>` assignments). High-entropy rules are gated by Shannon
entropy so placeholders like `YOUR_API_KEY_HERE` do not fire.

## PII

Email (low), US SSN (high), credit card (high, **Luhn-validated**), phone
(low confidence). Conservative by design — a backend full of false PII alarms
trains people to ignore it.

## Prompt injection

Weighted signature scoring: instruction-override, persona-switch,
prompt-exfiltration, delimiter spoofing, concealment orders, encoded-payload
execution, markdown exfil links, authority spoofing, invisible-unicode runs.
The **system prompt is exempt** (your own rules live there). Payloads arriving
through a tool output, tool description, or memory write are **indirect
injection** and escalated in severity.

## Tool poisoning

Hidden-instruction blocks (`<IMPORTANT>…</IMPORTANT>`), "don't tell the user",
sensitive-file reads, side-channel exfiltration, precondition hijacks, and
"always include this parameter". Primary surface is the **tool description**
(MCP `list_tools`) — the classic tool-poisoning vector — and also tool outputs
(rug-pull servers).

## Scope

Optional tool **allowlist** (`scope_allowed_tools`) — any other tool call is a
violation — plus sensitive-path access in tool arguments (`~/.ssh`,
`.aws/credentials`, `/etc/shadow`, `.env`, …).

## Memory poisoning

Runs on memory writes. Flags standing-order phrasing ("from now on…", "always
respond…", "never mention…") and, worse, **persistent injection** — an injection
signature written into durable memory is critical because it re-fires every
future turn.

## Anomalous sequence

Per-trace stateful. Flags the same tool called with identical input ≥
`repeat_threshold` times, A→B→A→B ping-pong, and tool fan-out beyond
`tool_fanout_threshold`.

## Cost / loop

Per-trace stateful. `cost_anomaly` when model calls exceed `llm_call_budget`;
`loop_anomaly` when the same prompt repeats ≥ `repeat_threshold` times.

## Local-LLM injection (opt-in)

Off by default. A local model (Ollama by default) classifies untrusted content
for injection. See [Local-LLM detector](llm.md).
