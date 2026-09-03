import os
import json
from typing import Dict, Any, List

try:
    from google import genai
    from google.genai import types
except ImportError:
    genai = None
    types = None


class ReportTranslatorV2:
    """
    On-Demand / Silent Background Translator for ScamLess Intelligence Reports.
    Translates English report content into Urdu Script and Roman Urdu simultaneously.
    """

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.client = None
        if self.api_key and genai:
            try:
                self.client = genai.Client(api_key=self.api_key)
            except Exception as e:
                print(f"Error initializing Gemini client in ReportTranslatorV2: {e}")

    def translate_report(self, report_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translates executive summary, key findings, red flags, and recommended actions
        into Urdu Script (ur) and Roman Urdu (roman_ur).
        """
        if not self.client:
            return {"status": "error", "message": "Gemini client unavailable"}

        summary = report_payload.get("summary", "")
        key_findings = report_payload.get("key_findings", [])
        red_flags = report_payload.get("red_flags", [])
        recommended_actions = report_payload.get("recommended_actions", [])

        prompt = f"""
You are an expert Urdu and Roman Urdu translator specializing in cybersecurity and job scam detection for Pakistani users.

Translate the following English report blocks into TWO formats:
1. "ur": Authentic Urdu script (Nastaliq vocabulary, Urdu alphabet).
2. "roman_ur": Natural Roman Urdu (Latin alphabet, e.g. "Yeh job offer aik fake fee trap scam hai...").

ENGLISH INPUT:
- Executive Summary: {summary}
- Key Findings: {json.dumps(key_findings, ensure_ascii=False)}
- Red Flags: {json.dumps(red_flags, ensure_ascii=False)}
- Recommended Actions: {json.dumps(recommended_actions, ensure_ascii=False)}

OUTPUT REQUIREMENT:
Return ONLY valid JSON matching this exact structure:
{{
  "ur": {{
    "summary": "Urdu script translation of summary",
    "key_findings": ["Urdu item 1", "Urdu item 2"],
    "red_flags": ["Urdu item 1", "Urdu item 2"],
    "recommended_actions": ["Urdu item 1", "Urdu item 2"]
  }},
  "roman_ur": {{
    "summary": "Roman Urdu translation of summary",
    "key_findings": ["Roman Urdu item 1", "Roman Urdu item 2"],
    "red_flags": ["Roman Urdu item 1", "Roman Urdu item 2"],
    "recommended_actions": ["Roman Urdu item 1", "Roman Urdu item 2"]
  }}
}}
"""
        try:
            response = self.client.models.generate_content(
                model="gemini-2.0-flash",
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    temperature=0.2,
                ),
            )
            raw_text = response.text
            data = json.loads(raw_text)
            return {"status": "success", "translations": data}
        except Exception as e:
            print(f"Error in translate_report: {e}")
            return {"status": "error", "message": str(e)}
