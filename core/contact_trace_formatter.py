import re
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional


class ContactTraceFormatter:
    """
    Converts raw OSINT evidence (phone-number searches and email-domain WHOIS)
    into the frontend ContactTrace schema.
    """

    SCAM_KEYWORDS = [
        "scam", "fraud", "complaint", "fake", "spam", "report",
        "cheat", "cheated", "rip-off", "ripoff", "fraudulent",
    ]

    @staticmethod
    def format(dossier: Dict[str, Any]) -> List[Dict[str, Any]]:
        traces: List[Dict[str, Any]] = []
        for db_match in dossier.get("community_db_matches", []):
            formatted_match = ContactTraceFormatter._format_db_match(db_match)
            if formatted_match:
                traces.append(formatted_match)

        for phone_search in dossier.get("phone_number_searches", []):
            formatted_phone = ContactTraceFormatter._format_phone(phone_search)
            if formatted_phone:
                traces.append(formatted_phone)

        for email_intel in dossier.get("email_domain_intelligence", []):
            formatted_email = ContactTraceFormatter._format_email(email_intel)
            if formatted_email:
                traces.append(formatted_email)

        # Deduplicate traces by value
        seen = set()
        unique_traces = []
        for t in traces:
            val_key = f"{t.get('type')}:{str(t.get('value', '')).lower().strip()}"
            if val_key not in seen:
                seen.add(val_key)
                unique_traces.append(t)

        return unique_traces

    @staticmethod
    def _format_db_match(db_match: Dict[str, Any]) -> Dict[str, Any]:
        dossier_id = db_match.get("dossier_id", "")
        entity_type = db_match.get("entity_type", "organization")
        entity_val = db_match.get("entity_value", "")
        risk_lvl = db_match.get("risk_level", "likely_scam")
        evidence = db_match.get("evidence_summary", "Community Threat Database Flag")

        return {
            "type": "database_match",
            "value": entity_val.upper() if entity_type == "organization" else entity_val,
            "entity_type": entity_type,
            "search_status": "ok",
            "risk_signal": "flagged",
            "findings": [
                {
                    "source_url": f"https://naukrinigran.vercel.app/report/{dossier_id}" if dossier_id else "",
                    "source_title": f"Naukri Nigran Community Threat Database ({risk_lvl.upper()})",
                    "snippet": evidence,
                }
            ],
        }

    @staticmethod
    def _normalize_phone(raw: str) -> str:
        digits = re.sub(r"\D", "", raw)
        if digits.startswith("92") and len(digits) == 12:
            return "0" + digits[2:]
        if digits.startswith("3") and len(digits) == 10:
            return "0" + digits
        if digits.startswith("03") and len(digits) == 11:
            return digits
        return digits or raw

    @staticmethod
    def _format_phone(phone_search: Dict[str, Any]) -> Dict[str, Any]:
        value = phone_search.get("target_phone_number", "")
        results = phone_search.get("results", [])
        status = phone_search.get("search_status", "failed")

        findings = []
        for r in results[:5]:
            url = r.get("href") or r.get("url", "")
            title = r.get("title", "")
            snippet = r.get("body") or r.get("snippet", "")
            if not url:
                continue
            findings.append({
                "source_url": url,
                "source_title": title,
                "snippet": snippet,
            })

        risk_signal = "unknown"
        if status == "ok" and findings:
            text_to_check = " ".join(
                f"{(f.get('source_title') or '')} {(f.get('snippet') or '')}".lower()
                for f in findings
            )
            if any(kw in text_to_check for kw in ContactTraceFormatter.SCAM_KEYWORDS):
                risk_signal = "flagged"
            else:
                risk_signal = "clean"
        elif status == "no_results":
            risk_signal = "clean"

        return {
            "type": "phone",
            "value": value,
            "normalized": ContactTraceFormatter._normalize_phone(value),
            "search_status": status,
            "findings": findings,
            "risk_signal": risk_signal,
        }

    @staticmethod
    def _format_email(email_intel: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        value = email_intel.get("sample_email", "")
        domain = email_intel.get("email_domain", "")

        # Ignore invalid non-email/non-domain strings (e.g. raw org name 'codealpha')
        if not value and not domain:
            return None
        if "@" not in str(value) and "." not in str(domain):
            return None

        creation_date = email_intel.get("whois_creation_date")
        whois_status = email_intel.get("whois_lookup_status", "failed")

        risk_signal = "unknown"
        if whois_status == "ok" and creation_date:
            try:
                created = datetime.strptime(creation_date, "%Y-%m-%d")
                if datetime.now() - created < timedelta(days=365):
                    risk_signal = "new_domain"
                else:
                    risk_signal = "clean"
            except Exception:
                risk_signal = "unknown"
        elif whois_status == "failed":
            risk_signal = "suspicious"

        return {
            "type": "email",
            "value": value,
            "domain": domain,
            "whois_creation_date": creation_date,
            "whois_lookup_status": "ok" if whois_status in ("ok", "no_date") else "failed",
            "risk_signal": risk_signal,
        }
