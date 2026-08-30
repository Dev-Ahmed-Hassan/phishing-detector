import os
import re
import json
from typing import List, Dict, Any, Optional, Literal
from datetime import datetime
from pydantic import BaseModel, Field, field_validator

try:
    from google import genai
    from google.genai import types
except ImportError:
    genai = None
    types = None


# ==========================================================================
# Pydantic Output Schema
# ==========================================================================

class VerifiedFact(BaseModel):
    claim: str
    evidence_status: Literal["confirmed", "contradicted", "unverified"]
    snippet_quote: str
    source_url: str
    source_type: str
    search_intent: str
    weight: Literal["high", "medium", "low"]


class RedFlag(BaseModel):
    flag: str
    technical_basis: str
    snippet_quote: str
    source_url: str
    source_type: str
    weight: Literal["high", "medium"]


class LinkOfInterest(BaseModel):
    title: str
    url: str
    category: str
    explanation: str


class ThreatVector(BaseModel):
    vector: str
    technical_grounding: str
    contributing_evidence: List[str]
    severity: Literal["high", "medium", "low"]


class Uncertainty(BaseModel):
    what_is_missing: str
    why_it_matters: str
    suggested_user_action: str


class UserFacingReport(BaseModel):
    title: str
    summary_paragraph: str
    what_we_checked: List[str]
    what_you_should_do: List[str]


class DiscardedEvidence(BaseModel):
    source_url: str
    title: Optional[str] = None
    reason: Literal["entity_mismatch", "paywall", "ad", "unrelated", "source_not_in_dossier"]
    note: Optional[str] = None


class ExecutiveSummary(BaseModel):
    verdict: Literal["likely_legitimate", "suspicious", "likely_scam", "inconclusive"]
    confidence_score: int = Field(0, ge=0, le=100)
    primary_threat_vector: str
    one_sentence_takeaway: Dict[str, str]


class JudgeReport(BaseModel):
    metadata: Dict[str, Any]
    executive_summary: ExecutiveSummary
    verified_facts: List[VerifiedFact]
    red_flags: List[RedFlag]
    links_of_interest: Dict[str, List[LinkOfInterest]]
    threat_vectors: List[ThreatVector]
    uncertainties: List[Uncertainty]
    user_facing_report: UserFacingReport
    discarded_evidence: List[DiscardedEvidence]
    confidence_justification: str


# ==========================================================================
# Judge Implementation
# ==========================================================================

class JudgeV2:
    """
    Phase 3: AI Judgment Agent.

    Consumes the structured OSINT dossier from OSINTCollectorV2 and produces:
    - A verdict with deterministic confidence score
    - Verified facts and red flags, each grounded in a snippet quote
    - Categorized links of interest
    - Technical threat vectors
    - A user-facing report in the original language

    Safety guards:
    - Pydantic schema validation on every output
    - URL allowlist: any citation not present in the dossier is discarded
    - Deterministic confidence scoring computed in Python
    - Multi-key Gemini rotation for free-tier rate limits
    """

    VALID_SOURCE_TYPES = {
        "linkedin", "official_website", "scam_report", "review_site", "news_blog",
        "whois", "phone_lookup", "claim_source", "government_tld", "email_domain",
        "unknown"
    }

    URDU_SCRIPT_REGEX = re.compile(r'[\u0600-\u06FF]')

    def __init__(self, api_key: Optional[str] = None, model: str = "gemini-3.5-flash-lite"):
        self.model = model
        self.clients = []

        if api_key:
            self.clients.append(genai.Client(api_key=api_key))
        else:
            for key_name in ["GEMINI_API_KEY", "GEMINI_API_KEY_2", "GEMINI_API_KEY_3", "GEMINI_API"]:
                key = os.getenv(key_name)
                if key and genai:
                    self.clients.append(genai.Client(api_key=key))

    def judge(
        self,
        dossier: Dict[str, Any],
        user_language: str = "english",
        original_message: Optional[str] = None,
        max_retries: int = 3
    ) -> Dict[str, Any]:
        """
        Main entry point. Returns a validated JudgeReport as a dict.

        If original_message is provided, Urdu script is detected deterministically
        in Python; otherwise language is set to "auto" and the model must match
        the original message's language (Urdu script / Roman Urdu / English).
        """
        if not self.clients:
            raise RuntimeError("No Gemini API keys available. Set GEMINI_API_KEY.")

        if original_message:
            if self.URDU_SCRIPT_REGEX.search(original_message):
                user_language = "urdu"
            else:
                user_language = "auto"

        dossier = self._prepare_dossier(dossier)
        url_allowlist = self._build_url_allowlist(dossier)
        target_entity = dossier.get("target_entity_name") or "Unknown Entity"

        system_prompt = self._build_system_prompt(user_language, target_entity)
        user_prompt = self._build_user_prompt(dossier, user_language, original_message)

        last_error = None
        for attempt in range(max_retries):
            for client in self.clients:
                try:
                    raw_json = self._call_model(client, system_prompt, user_prompt)
                    validated = self._post_process(
                        raw_json=raw_json,
                        dossier=dossier,
                        url_allowlist=url_allowlist,
                        user_language=user_language,
                        target_entity=target_entity
                    )
                    return validated
                except Exception as e:
                    last_error = e
                    error_message = str(e).lower()
                    if any(err in error_message for err in ["429", "quota", "rate limit", "503", "unavailable"]):
                        continue
                    break

        raise RuntimeError(f"JudgeV2 failed after {max_retries} attempts. Last error: {last_error}")

    # ----------------------------------------------------------------------
    # Prompt Construction
    # ----------------------------------------------------------------------

    def _build_system_prompt(self, user_language: str, target_entity: str) -> str:
        schema_json = JudgeReport.model_json_schema()

        return f"""You are a forensic fact-checker for a Pakistani job-scam detection system.

YOUR ONLY JOB: Read the provided OSINT dossier and decide what is true, false, or unverified. Do not search the web. Do not invent facts. Do not make risk judgments beyond what the evidence supports.

TARGET ENTITY: "{target_entity}"
USER LANGUAGE: {user_language}

OUTPUT RULES:
1. Respond ONLY with a single valid JSON object matching the schema below. No markdown, no preamble, no explanation outside the JSON.
2. Every `verified_fact` and `red_flag` MUST include a `snippet_quote` copied EXACTLY from the dossier's `search_snippet` or `full_page_content`.
3. If you cannot find a verbatim quote for a claim, do not include that claim.
4. `source_url` MUST be a URL that exists in the provided dossier.
5. `source_type` MUST be one of: linkedin, official_website, scam_report, review_site, news_blog, whois, phone_lookup, claim_source, government_tld, email_domain, unknown.
6. Before using any search result, check that it actually refers to the target entity "{target_entity}". If it refers to a different company, person, or product with the same name, put it in `discarded_evidence` with reason "entity_mismatch".
7. If a result is clearly an ad, a login/paywall wall with no usable snippet, or completely unrelated, put it in `discarded_evidence` with reason "ad", "paywall", or "unrelated".
8. Set `executive_summary.confidence_score` to 0. Python will compute it deterministically.
9. Write `user_facing_report.summary_paragraph` and `one_sentence_takeaway.user_language` in {user_language}. Write `one_sentence_takeaway.en` in English.
   LANGUAGE RESOLUTION: the USER LANGUAGE is either a concrete language ("urdu", "roman_urdu", "english") or "auto".
   - If it is "auto": read the ORIGINAL MESSAGE at the top of the user prompt, detect its language and script, and write all user-facing prose in that EXACT language and script. Urdu script input (اردو حروف) → reply in Urdu script. Roman Urdu input (Latin letters with Urdu vocabulary like "kya", "hai", "krna") → reply in Roman Urdu. English input → reply in English.
   - If it is a concrete language, always use it.
10. `weight` values: "high" for official presence / direct contradictions / WHOIS domain age; "medium" for community reports and reviews; "low" for weak or single-source signals.

STEP-BY-STEP REASONING (think in this order, but do not output your reasoning):
1. Identify the target entity from the dossier.
2. Build a baseline of official presence: LinkedIn page and official website from `official_presence_searches`.
3. Check each `url_verification`: domain age, TLD, HTTP status, redirect warnings.
4. Check each `community_scam_searches` result for entity match. If the result is a scam report, fraud warning, or serious complaint, create a red_flag. If it is a normal review or positive mention, create a verified_fact.
5. Check each `claim_verification`: is the claim confirmed, contradicted, or unverified by the search results?
6. Check `phone_number_searches` and `email_domain_intelligence` for any warning signals.
7. Build `threat_vectors` only when at least two separate evidence items support the same pattern. Example patterns:
   - Impersonation: official presence exists but the message URL/phone/email does not match.
   - Newly created trap domain: domain age < 6 months and no matching official presence.
   - Reputation collapse: multiple scam/complaint reports about the exact entity.
   - Unverifiable offer: claims have no web evidence and entity has thin footprint.
8. Fill `uncertainties` with anything important that could not be verified.
9. Fill `links_of_interest` with the most relevant URLs, grouped by category, each with a one-sentence explanation.

EXAMPLE SNIPPET FORMAT:
{{
  "claim": "CodeAlpha has an active LinkedIn company page.",
  "evidence_status": "confirmed",
  "snippet_quote": "CodeAlpha | LinkedIn ... 597,131 followers",
  "source_url": "https://in.linkedin.com/company/codealpha",
  "source_type": "linkedin",
  "search_intent": "Find official corporate LinkedIn profile for 'CodeAlpha'",
  "weight": "high"
}}

JSON SCHEMA:
{json.dumps(schema_json, indent=2)}
"""

    def _build_user_prompt(self, dossier: Dict[str, Any], user_language: str, original_message: Optional[str] = None) -> str:
        message_block = ""
        if original_message:
            snippet = original_message[:600]
            message_block = f"""ORIGINAL MESSAGE (the user's input — use its language/script for user-facing prose):
\"\"\"{snippet}\"\"\"

"""

        return f"""{message_block}OSINT DOSSIER (analyze this and return only JSON):

```json
{json.dumps(dossier, ensure_ascii=False, indent=2)}
```

Remember:
- User language: {user_language}
- Confidence score should be 0 (Python computes it)
- Every fact/flag needs a verbatim snippet_quote
- Discard irrelevant or mismatched results explicitly
"""

    # ----------------------------------------------------------------------
    # Model Call
    # ----------------------------------------------------------------------

    def _call_model(self, client, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        response = client.models.generate_content(
            model=self.model,
            contents=[user_prompt],
            config=types.GenerateContentConfig(
                system_instruction=system_prompt,
                temperature=0.0,
                response_mime_type="application/json"
            )
        )

        raw_content = response.text.strip()
        if raw_content.startswith("```json"):
            raw_content = raw_content[7:-3].strip()
        elif raw_content.startswith("```"):
            raw_content = raw_content[3:-3].strip()

        return json.loads(raw_content)

    # ----------------------------------------------------------------------
    # Dossier Preparation & URL Allowlist
    # ----------------------------------------------------------------------

    def _prepare_dossier(self, dossier: Dict[str, Any]) -> Dict[str, Any]:
        """
        Truncate very long full_page_content fields to keep prompt size reasonable.
        """
        MAX_CONTENT_LEN = 1200

        def truncate(obj):
            if isinstance(obj, dict):
                new = {}
                for k, v in obj.items():
                    if k == "full_page_content" and isinstance(v, str) and len(v) > MAX_CONTENT_LEN:
                        new[k] = v[:MAX_CONTENT_LEN] + "... [truncated]"
                    else:
                        new[k] = truncate(v)
                return new
            elif isinstance(obj, list):
                return [truncate(item) for item in obj]
            return obj

        return truncate(dossier)

    def _build_url_allowlist(self, dossier: Dict[str, Any]) -> set:
        urls = set()

        for item in dossier.get("url_verifications", []):
            if item.get("target_url"):
                urls.add(item["target_url"])

        for search in dossier.get("official_presence_searches", []):
            for r in search.get("results", []):
                if r.get("url"):
                    urls.add(r["url"])

        for candidate in dossier.get("official_site_candidates", []):
            if candidate.get("source_url"):
                urls.add(candidate["source_url"])

        for search in dossier.get("community_scam_searches", []):
            for r in search.get("results", []):
                if r.get("url"):
                    urls.add(r["url"])

        for search in dossier.get("claim_verifications", []):
            for r in search.get("results", []):
                if r.get("url"):
                    urls.add(r["url"])

        for search in dossier.get("phone_number_searches", []):
            for r in search.get("results", []):
                if r.get("url"):
                    urls.add(r["url"])

        return urls

    # ----------------------------------------------------------------------
    # Post-Processing: Validation, URL Filter, Confidence Score
    # ----------------------------------------------------------------------

    def _post_process(
        self,
        raw_json: Dict[str, Any],
        dossier: Dict[str, Any],
        url_allowlist: set,
        user_language: str,
        target_entity: str
    ) -> Dict[str, Any]:
        # Normalize source_type values
        raw_json = self._normalize_source_types(raw_json)

        # Build full URL allowlist including normalized variants
        normalized_allowlist = {self._normalize_url(u) for u in url_allowlist}

        # Filter out hallucinated URLs
        raw_json["verified_facts"] = self._filter_facts(
            raw_json.get("verified_facts", []), normalized_allowlist
        )
        raw_json["red_flags"] = self._filter_flags(
            raw_json.get("red_flags", []), normalized_allowlist
        )
        raw_json["links_of_interest"] = self._filter_links(
            raw_json.get("links_of_interest", {}), normalized_allowlist
        )

        # Ensure discarded_evidence exists
        if "discarded_evidence" not in raw_json:
            raw_json["discarded_evidence"] = []

        # Add any facts/flags with URLs not in dossier to discarded_evidence
        # (already handled by filter functions)

        # Compute deterministic confidence score
        confidence, justification = self._compute_confidence(
            raw_json, dossier, target_entity
        )

        raw_json["executive_summary"]["confidence_score"] = confidence
        raw_json["confidence_justification"] = justification

        # Ensure metadata is set
        raw_json["metadata"] = {
            "input_language": user_language,
            "target_entity": target_entity,
            "model": self.model,
            "temperature": 0.0,
            "total_facts": len(raw_json.get("verified_facts", [])),
            "total_red_flags": len(raw_json.get("red_flags", [])),
            "total_links_of_interest": sum(
                len(v) for v in raw_json.get("links_of_interest", {}).values()
            ),
            "total_discarded": len(raw_json.get("discarded_evidence", []))
        }

        # Validate with Pydantic
        report = JudgeReport(**raw_json)
        return report.model_dump()

    def _normalize_source_types(self, raw_json: Dict[str, Any]) -> Dict[str, Any]:
        for fact in raw_json.get("verified_facts", []):
            st = fact.get("source_type", "unknown").lower().strip()
            if st not in self.VALID_SOURCE_TYPES:
                fact["source_type"] = "unknown"
        for flag in raw_json.get("red_flags", []):
            st = flag.get("source_type", "unknown").lower().strip()
            if st not in self.VALID_SOURCE_TYPES:
                flag["source_type"] = "unknown"
        return raw_json

    def _normalize_url(self, url: str) -> str:
        url = url.strip().lower()
        url = url.replace("https://", "").replace("http://", "")
        url = url.replace("www.", "")
        if url.endswith("/"):
            url = url[:-1]
        return url

    def _filter_facts(self, facts: List[Dict[str, Any]], allowlist: set) -> List[Dict[str, Any]]:
        valid = []
        for fact in facts:
            url = fact.get("source_url", "")
            norm = self._normalize_url(url)
            if norm in allowlist:
                valid.append(fact)
        return valid

    def _filter_flags(self, flags: List[Dict[str, Any]], allowlist: set) -> List[Dict[str, Any]]:
        valid = []
        for flag in flags:
            url = flag.get("source_url", "")
            norm = self._normalize_url(url)
            if norm in allowlist:
                valid.append(flag)
        return valid

    def _filter_links(self, links_dict: Dict[str, List[Dict[str, Any]]], allowlist: set) -> Dict[str, List[Dict[str, Any]]]:
        filtered = {}
        for category, links in links_dict.items():
            clean = []
            for link in links:
                url = link.get("url", "")
                norm = self._normalize_url(url)
                if norm in allowlist:
                    clean.append(link)
            if clean:
                filtered[category] = clean
        return filtered

    # ----------------------------------------------------------------------
    # Deterministic Confidence Scoring
    # ----------------------------------------------------------------------

    def _compute_confidence(
        self,
        report: Dict[str, Any],
        dossier: Dict[str, Any],
        target_entity: str
    ) -> tuple:
        """
        Deterministic confidence/risk score.

        Score is interpreted as trust in the entity's legitimacy:
        - 70-100: likely_legitimate
        - 30-69:  suspicious
        - 0-29:   likely_scam

        To prevent a verbose model from collapsing the score with duplicate
        penalties for the same source, only the top 2 red flags by weight and
        the single top threat vector by severity contribute to scoring.
        """
        score = 50
        reasons = []

        # 1. Official presence signals
        has_linkedin = any(
            f.get("source_type") == "linkedin" and f.get("evidence_status") == "confirmed"
            for f in report.get("verified_facts", [])
        )
        has_official_website = any(
            f.get("source_type") == "official_website" and f.get("evidence_status") == "confirmed"
            for f in report.get("verified_facts", [])
        )

        if has_linkedin and has_official_website:
            score += 20
            reasons.append("Strong official presence (LinkedIn + official website confirmed): +20")
        elif has_linkedin or has_official_website:
            score += 12
            reasons.append("Partial official presence: +12")

        # 2. Domain age signals
        old_domains = 0
        new_domains = 0
        for uv in dossier.get("url_verifications", []):
            creation_date = uv.get("whois_creation_date")
            if creation_date:
                try:
                    parsed = datetime.strptime(creation_date, "%Y-%m-%d")
                    days_old = (datetime.now() - parsed).days
                    if days_old > 365:
                        old_domains += 1
                    elif days_old < 180:
                        new_domains += 1
                except Exception:
                    pass

        for cand in dossier.get("official_site_candidates", []):
            creation_date = cand.get("whois_creation_date")
            if creation_date:
                try:
                    parsed = datetime.strptime(creation_date, "%Y-%m-%d")
                    days_old = (datetime.now() - parsed).days
                    if days_old > 365:
                        old_domains += 1
                    elif days_old < 180:
                        new_domains += 1
                except Exception:
                    pass

        if old_domains > 0:
            score += 10
            reasons.append(f"Domain(s) older than 1 year found ({old_domains}): +10")
        if new_domains > 0:
            score -= 12
            reasons.append(f"Very new domain(s) found ({new_domains}): -12")

        # 3. Red flags — top 2 by weight only (prevents duplicate-source inflation)
        weight_values = {"high": 12, "medium": 6, "low": 2}
        flags = report.get("red_flags", [])
        sorted_flags = sorted(
            flags,
            key=lambda f: weight_values.get(f.get("weight", "low"), 0),
            reverse=True
        )
        top_flags = sorted_flags[:2]
        flag_penalty = 0
        for f in top_flags:
            w = f.get("weight", "low")
            p = weight_values.get(w, 0)
            flag_penalty += p
            reasons.append(f"{w}-weight red flag: -{p}")
        score -= flag_penalty

        # 4. Threat vectors — single top vector only
        severity_values = {"high": 10, "medium": 5, "low": 2}
        vectors = report.get("threat_vectors", [])
        if vectors:
            top_vector = max(
                vectors,
                key=lambda v: severity_values.get(v.get("severity", "low"), 0)
            )
            sev = top_vector.get("severity", "low")
            p = severity_values.get(sev, 0)
            score -= p
            reasons.append(f"Top threat vector severity ({sev}): -{p}")

        # 5. Missing critical evidence penalty
        if not has_linkedin and not has_official_website:
            score -= 10
            reasons.append("No verifiable official presence found: -10")

        # 6. No evidence at all
        total_evidence = len(report.get("verified_facts", [])) + len(flags) + len(vectors)
        if total_evidence == 0:
            score = 50
            reasons.append("No usable evidence collected; score reset to neutral: 50")

        # Clamp
        score = max(0, min(100, score))

        justification = "Base score: 50. " + " ".join(reasons) + f" Final score: {score}."
        return score, justification
