import os
import json
from typing import List, Dict, Any
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
    Background translation engine for ScamLess investigation dossiers.
    Pre-translates English scan reports into Urdu Script (`ur`) and Roman Urdu (`roman_ur`)
    with zero latency impact on the primary scan verdict.
    """

    def __init__(self):
        self.clients = []
        for key_name in ["GEMINI_API_KEY", "GEMINI_API_KEY_2", "GEMINI_API_KEY_3", "GEMINI_API"]:
            key = os.getenv(key_name)
            if key and genai:
                self.clients.append(genai.Client(api_key=key))

    def translate_report(
        self,
        summary: str,
        key_findings: List[str],
        red_flags: List[str],
        recommended_actions: List[str]
    ) -> Dict[str, Any]:
        if not self.clients:
            print("[ReportTranslatorV2] No Gemini API clients initialized.")
            return {"status": "error", "message": "Gemini API client unavailable"}

        prompt = f"""You are an expert Urdu and Roman Urdu translator specializing in anti-scam intelligence dossiers for Pakistani users.
Translate the following English scam report elements into TWO formats:
1) `ur`: Formal, natural Urdu script (اردو رسم الخط).
2) `roman_ur`: Clear Roman Urdu (Urdu written in Latin alphabet, as used in Pakistan mobile messaging).

ENGLISH INPUT DETAILS:
Summary: {summary}
Key Findings: {json.dumps(key_findings)}
Red Flags: {json.dumps(red_flags)}
Recommended Actions: {json.dumps(recommended_actions)}

CRITICAL CONSTRAINTS:
- `ur.key_findings`, `ur.red_flags`, `ur.recommended_actions` MUST have the EXACT SAME array length as input arrays ({len(key_findings)}, {len(red_flags)}, {len(recommended_actions)} items respectively).
- `roman_ur.key_findings`, `roman_ur.red_flags`, `roman_ur.recommended_actions` MUST have the EXACT SAME array length as input arrays.
- Keep tone professional, urgent, and clear.
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
                    print(f"[ReportTranslatorV2] Model {model_name} failed: {e}")
                    continue

        return {"status": "error", "message": "All translation API attempts failed"}
