import os
import json
from typing import List, Dict, Any, Optional
from pydantic import BaseModel

try:
    from google import genai
    from google.genai import types
except ImportError:
    genai = None
    types = None


class LangTranslation(BaseModel):
    summary: str
    key_findings: List[str]
    red_flags: List[str]
    recommended_actions: List[str]


class TranslationResponseSchema(BaseModel):
    ur: LangTranslation
    roman_ur: LangTranslation


class ReportTranslatorV2:
    """
    On-Demand & Background Pre-translation Engine for ScamLess Investigation Dossiers.
    Translates English scan reports into Urdu Script (`ur`) and Roman Urdu (`roman_ur`)
    simultaneously with multi-key Gemini API rotation.
    """

    def __init__(self, api_key: Optional[str] = None):
        self.clients = []
        if api_key and genai:
            try:
                self.clients.append(genai.Client(api_key=api_key))
            except Exception as e:
                print(f"[ReportTranslatorV2] Provided API key initialization failed: {e}")

        if not self.clients and genai:
            for key_name in ["GEMINI_API_KEY", "GEMINI_API_KEY_2", "GEMINI_API_KEY_3", "GEMINI_API"]:
                key = os.getenv(key_name)
                if key:
                    try:
                        self.clients.append(genai.Client(api_key=key))
                    except Exception as e:
                        print(f"[ReportTranslatorV2] Key {key_name} initialization failed: {e}")

    def translate_report(
        self,
        summary: str = "",
        key_findings: Optional[List[str]] = None,
        red_flags: Optional[List[str]] = None,
        recommended_actions: Optional[List[str]] = None,
        report_payload: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Translates report summary, key findings, red flags, and recommended actions
        into Urdu Script (ur) and Roman Urdu (roman_ur). Accepts either explicit arguments
        or a payload dictionary.
        """
        if not self.clients:
            print("[ReportTranslatorV2] No active Gemini API clients available.")
            return {"status": "error", "message": "Gemini API client unavailable"}

        if report_payload:
            summary = summary or report_payload.get("summary", "")
            key_findings = key_findings or report_payload.get("key_findings", [])
            red_flags = red_flags or report_payload.get("red_flags", [])
            recommended_actions = recommended_actions or report_payload.get("recommended_actions", [])

        key_findings = key_findings or []
        red_flags = red_flags or []
        recommended_actions = recommended_actions or []

        prompt = f"""You are an expert Urdu and Roman Urdu translator specializing in cybersecurity and job-scam detection for Pakistani users.
Translate the following English scam report elements into TWO formats:
1) `ur`: Authentic Urdu script (اردو رسم الخط using standard vocabulary).
2) `roman_ur`: Natural Roman Urdu (Latin alphabet, e.g., "Yeh job offer aik fake fee trap scam hai...").

ENGLISH INPUT DETAILS:
Summary: {summary}
Key Findings: {json.dumps(key_findings, ensure_ascii=False)}
Red Flags: {json.dumps(red_flags, ensure_ascii=False)}
Recommended Actions: {json.dumps(recommended_actions, ensure_ascii=False)}

CRITICAL CONSTRAINTS:
- `ur.key_findings`, `ur.red_flags`, `ur.recommended_actions` MUST have the EXACT SAME array length as input arrays ({len(key_findings)}, {len(red_flags)}, {len(recommended_actions)} items respectively).
- `roman_ur.key_findings`, `roman_ur.red_flags`, `roman_ur.recommended_actions` MUST have the EXACT SAME array length as input arrays.
- Tone must be clear, urgent, and professional.
"""

        models_to_try = ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash"]

        for client in self.clients:
            for model_name in models_to_try:
                try:
                    response = client.models.generate_content(
                        model=model_name,
                        contents=[prompt],
                        config=types.GenerateContentConfig(
                            response_mime_type="application/json",
                            response_schema=TranslationResponseSchema,
                            temperature=0.2
                        )
                    )
                    if response and response.text:
                        parsed = json.loads(response.text)
                        return {"status": "success", "translations": parsed}
                except Exception as e:
                    print(f"[ReportTranslatorV2] Model {model_name} attempt failed: {e}")
                    continue

        return {"status": "error", "message": "All translation API attempts failed"}
