"""Stage A of the Watcher: turn one alert into testable hypotheses.

The hunt engine tests hypotheses; it never invents them. Today a human authors
the hypothesis + scope + context in the console. The Hypothesizer *is* that human
for an incoming alert — it reads an (already enriched) finding and produces the
``WatcherHypothesisSet`` a hunt needs to run.

A human doesn't hypothesize from the raw alert alone — they first check what the
entities *are*. So the Hypothesizer gathers context before it reasons:

- **Reputation (facts):** VirusTotal / Shodan / local-feed hits already attached to
  the finding by the daemon's enrichment step — "is this IOC known-bad".
- **Asset context:** deliberately absent — no host-role / user-privilege source
  exists yet (accepted gap). The prompt says so, so the model knows it is blind
  there rather than guessing.

What it does NOT feed the model: triage's ``category`` / ``recommended_action``.
Those are a prior one-shot LLM guess made before any evidence; piping a guess into
a guess just anchors this one. Only hard facts inform the hypothesis.

Split of responsibility, on purpose:

- **Deterministic (facts from the alert):** ``scope`` and any MITRE techniques the
  finding already carries. The model does not get to invent or drop them.
- **Model (judgement):** the hypotheses, a short narrative, inferred techniques
  when the source gave none, and the data domains worth searching.

The LLM call reuses the daemon's existing gateway (Bifrost-routed, cost-tracked) —
the same path triage uses. No LLM client is constructed here.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional

from services.daemon.watcher.schemas import WatcherHypothesisSet

logger = logging.getLogger(__name__)

# How many entity buckets we recognize as scope, and the source keys (plural and
# singular) each maps from. Findings arrive from many normalizers; be tolerant.
_SCOPE_KEYS: Dict[str, tuple] = {
    "src_ips": ("src_ips", "src_ip", "source_ip"),
    "dest_ips": ("dest_ips", "dest_ip", "dst_ip", "destination_ip"),
    "hostnames": ("hostnames", "hostname", "host"),
    "usernames": ("usernames", "users", "username", "user"),
}

# Cap how much gathered context we pour into the prompt, so a noisy finding can't
# blow up the request.
_MAX_REPUTATION_LINES = 12


class HypothesizerError(Exception):
    """The Hypothesizer could not produce a valid hypothesis set for a finding."""


def _scope_from_entities(
    entity_context: Optional[Dict[str, Any]]
) -> Dict[str, List[str]]:
    """Collect the alert's real entities into the scope shape, tolerating the
    plural/singular key variants different normalizers emit. Facts only."""
    ctx = entity_context or {}
    scope: Dict[str, List[str]] = {}
    for bucket, source_keys in _SCOPE_KEYS.items():
        values: List[str] = []
        for key in source_keys:
            raw = ctx.get(key)
            if not raw:
                continue
            items = raw if isinstance(raw, list) else [raw]
            values.extend(str(v).strip() for v in items if str(v).strip())
        if values:
            # De-dup, preserve first-seen order.
            scope[bucket] = list(dict.fromkeys(values))
    return scope


def _reputation_lines(finding: Dict[str, Any]) -> List[str]:
    """Pull known-bad signals the daemon's enrichment already attached to the
    finding. Defensive: the enrichment shape drifts and two writers clobber the
    same column (see QUESTIONABLE.md Q2), so read tolerantly and skip what we
    don't recognize rather than trust a fixed schema."""
    enrichment = finding.get("enrichment")
    if not isinstance(enrichment, dict):
        return []

    lines: List[str] = []
    for key, value in enrichment.items():
        if not isinstance(value, dict):
            continue
        if key.startswith("ip_"):
            ip = key[3:]
            vt = value.get("virustotal") or {}
            shodan = value.get("shodan") or {}
            bits = []
            if vt.get("malicious"):
                mal, rep = vt.get("malicious"), vt.get("reputation")
                bits.append(f"VT malicious={mal}, reputation={rep}")
            if shodan.get("vulns"):
                bits.append(f"Shodan vulns={list(shodan.get('vulns'))[:5]}")
            if shodan.get("org"):
                bits.append(f"org={shodan.get('org')}")
            if bits:
                lines.append(f"IP {ip}: " + "; ".join(bits))
        elif key.startswith("hash_"):
            malicious = value.get("malicious")
            if malicious:
                names = list(value.get("names") or [])[:3]
                ftype = value.get("type")
                lines.append(
                    f"Hash {key[5:]}: VT malicious={malicious}, "
                    f"type={ftype}, names={names}"
                )
        elif key == "threat_indicators":
            for ind_key in list(value.keys())[:5]:
                lines.append(f"Threat-feed hit: {ind_key}")
        if len(lines) >= _MAX_REPUTATION_LINES:
            break
    return lines[:_MAX_REPUTATION_LINES]


def _build_prompt(
    finding: Dict[str, Any],
    scope: Dict[str, List[str]],
    reputation: List[str],
) -> str:
    """Ask the model for a JSON hypothesis set grounded in the alert + context."""
    desc = (finding.get("description") or "N/A")[:800]
    given_techniques = sorted((finding.get("mitre_predictions") or {}).keys())
    reputation_block = "\n    ".join(reputation) if reputation else "none found"

    return f"""You are a SOC analyst deciding what to investigate. Read the alert \
and the context below and state what an attacker could be doing, as hypotheses a \
hunt can test.

ALERT
  Finding ID: {finding.get('finding_id') or 'N/A'}
  Source: {finding.get('data_source') or 'unknown'}
  Severity (as the source reported it): {finding.get('severity') or 'unknown'}
  Title: {finding.get('title') or 'N/A'}
  Description: {desc}
  Entities in scope: {json.dumps(scope) or '{}'}
  MITRE signals from the source (may be tactics, not specific techniques): \
{given_techniques or 'none'}

CONTEXT (facts gathered on the entities — not guesses)
  Reputation (known-bad signals):
    {reputation_block}
  Asset context (is this host critical? is this user privileged?): NOT AVAILABLE \
— do not assume; if it would change your hypothesis, say so.

Return ONLY a JSON object, no prose, with these keys:
  "hypotheses": array of 1-4 strings. ATTACK hypotheses ONLY — each a concrete,
      falsifiable claim about attacker intent that names the entity involved
      (e.g. "the internal host 10.0.0.5 is conducting command-and-control with
      external 203.0.113.9"), NOT a vague statement like "something suspicious
      happened". Do NOT include the benign / "no attack" explanation — the hunt
      seeds and argues that null itself, so a benign alternative here just
      duplicates it. Claim only what the alert supports: if the protocol or
      technique is not in the data, do not invent it — leave the hunt to discover
      it. Ground them in the reputation/history facts above where relevant.
  "narrative": one or two sentences of context — what the alert saw and why it is
      worth a hunt.
  "attack_techniques": array of MITRE technique IDs (e.g. "T1071.004") you can
      justify from the alert. May be empty — do not guess a specific technique the
      data doesn't support.
  "data_domains": array naming where to look (e.g. "dns", "network", "endpoint",
      "auth", "web", "cloud"). May be empty.

If the alert is too thin to justify a specific hypothesis, still return your single
best falsifiable ATTACK claim at the coarsest honest level (e.g. "10.0.0.5 is
communicating with attacker-controlled 203.0.113.9") — never an empty array, and
never the benign explanation."""


def _extract_json(text: str) -> Dict[str, Any]:
    """Pull the JSON object out of a model reply that may wrap it in prose or
    ```json fences."""
    stripped = text.strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", stripped, re.DOTALL)
    if fenced:
        stripped = fenced.group(1)
    else:
        start = stripped.find("{")
        end = stripped.rfind("}") + 1
        if start != -1 and end > start:
            stripped = stripped[start:end]
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise HypothesizerError(f"model reply was not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise HypothesizerError("model reply JSON was not an object")
    return data


async def form_hypotheses(
    finding: Dict[str, Any],
    *,
    gateway: Any = None,
) -> WatcherHypothesisSet:
    """Form a testable hypothesis set from one enriched alert.

    ``gateway`` (optional) is the LLM gateway, injectable for tests. In the daemon
    it defaults to the shared one. Raises :class:`HypothesizerError` when no valid
    set can be built.
    """
    finding_id = finding.get("finding_id")
    if not finding_id:
        raise HypothesizerError("finding has no finding_id")

    scope = _scope_from_entities(finding.get("entity_context"))
    reputation = _reputation_lines(finding)

    if gateway is None:
        from core.llm.gateway.gateway import get_llm_gateway

        gateway = await get_llm_gateway()
    if gateway is None:
        raise HypothesizerError("LLM gateway unavailable")

    prompt = _build_prompt(finding, scope, reputation)
    reply = await gateway.submit_triage(prompt)
    if not reply:
        raise HypothesizerError("LLM gateway returned no reply")
    if isinstance(reply, dict):
        reply = reply.get("content", "")

    data = _extract_json(reply)

    # Merge the source's own techniques back in — an attested technique is a fact,
    # not a suggestion. But the source's MITRE signal can be a *tactic* name
    # (LogLM emits tactics, not technique IDs), and only T-code-shaped signals
    # belong in attack_techniques. The raw signal still reaches the model via the
    # prompt, so a tactic isn't lost — it just isn't mislabelled as a technique.
    given = [
        t
        for t in (finding.get("mitre_predictions") or {})
        if isinstance(t, str) and re.match(r"^T\d{4}", t)
    ]
    inferred = [t for t in (data.get("attack_techniques") or []) if isinstance(t, str)]
    techniques = list(dict.fromkeys([*given, *inferred]))

    try:
        return WatcherHypothesisSet(
            hypotheses=data.get("hypotheses") or [],
            narrative=data.get("narrative") or "",
            attack_techniques=techniques,
            data_domains=[
                d for d in (data.get("data_domains") or []) if isinstance(d, str)
            ],
            scope=scope,
            source_finding_id=finding_id,
        )
    except ValueError as exc:
        # Pydantic validation (e.g. empty hypotheses, blank narrative).
        raise HypothesizerError(
            f"model produced an invalid hypothesis set: {exc}"
        ) from exc
