from pydantic import BaseModel
from typing import Optional
import os
import json
from google import genai
from google.genai import types

class ModularReport(BaseModel):
    risk_level: str                 # "High", "Medium", "Low"
    detected_language: str          # e.g., "Roman Urdu", "Urdu", "English"
    specific_analysis: str          # Context-specific explanation of what is fishy
    database_findings: Optional[str] = None   
    web_search_findings: Optional[str] = None 
    recommended_action: str         # Actionable advice in the user's language

class LLMProvider:
    def analyze(self, text: str) -> ModularReport:
        raise NotImplementedError("Subclasses must implement this method")

class GeminiLLMProvider(LLMProvider):
    def __init__(self, api_key: str):
        self.client = genai.Client(api_key=api_key)
        self.model = "gemini-3.5-flash-lite" 

        self.system_instruction = """
        You are an expert scam and phishing detector specializing in Pakistani job scams.
        
        CRITICAL INSTRUCTIONS:
        1. Analyze the provided job offer or recruiter message carefully.
        2. Language Match: You MUST reply in the exact same language the user used (Urdu, Roman Urdu, or English). If they text in Roman Urdu, your `specific_analysis` and `recommended_action` MUST be in Roman Urdu.
        3. Be Specific: Do not use generic warnings. Point out exactly which sentence, salary figure, or fee request in their text is suspicious. If it mentions a specific company or number, reference it.
        
        Check for:
        - Upfront fees / Registration fees / Processing fees
        - Unrealistic salaries for the described role
        - High-pressure urgency (e.g., "Reply within 10 minutes")
        - Suspicious links or unverifiable company details
        
        Respond ONLY with a JSON object in this exact format, nothing else:
        {
            "risk_level": "High" | "Medium" | "Low",
            "detected_language": "Roman Urdu",
            "specific_analysis": "Specifically explain what is fishy in their message using their language.",
            "recommended_action": "Tell them exactly what to do next in their language (e.g., block the number, don't pay)."
        }
        """

    def analyze(self, text: str) -> ModularReport:
        response = self.client.models.generate_content(
            model=self.model,
            contents=text,
            config=types.GenerateContentConfig(
                system_instruction=self.system_instruction,
                temperature=0.2,
                response_mime_type="application/json"
            )
        )
        
        raw_content = response.text.strip()
        if raw_content.startswith("```json"):
            raw_content = raw_content[7:-3].strip()
        elif raw_content.startswith("```"):
            raw_content = raw_content[3:-3].strip()
            
        data = json.loads(raw_content)
        
        return ModularReport(
            risk_level=data.get("risk_level", "Medium"),
            detected_language=data.get("detected_language", "English"),
            specific_analysis=data.get("specific_analysis", "Could not fully parse reasoning."),
            recommended_action=data.get("recommended_action", "Be careful and verify the source."),
            database_findings=None,
            web_search_findings=None
        )


class OrchestratorLLMProvider(LLMProvider):
    """
    Manages multiple LLM providers and API keys to route around rate limits (429).
    """
    def __init__(self):
        self.providers = []
        
        # Load all available Gemini Keys (GEMINI_API_KEY, GEMINI_API_KEY_2, etc.)
        for key_name in ["GEMINI_API_KEY", "GEMINI_API_KEY_2", "GEMINI_API_KEY_3"]:
            api_key = os.getenv(key_name)
            if api_key:
                self.providers.append(GeminiLLMProvider(api_key=api_key))
                
        self.current_idx = 0

    def analyze(self, text: str) -> ModularReport:
        if not self.providers:
            return self._fallback_error("No API keys configured.")

        attempts = 0
        while attempts < len(self.providers):
            provider = self.providers[self.current_idx]
            try:
                return provider.analyze(text)
            except Exception as e:
                error_message = str(e).lower()
                
                # If it's a rate limit or 503 server overload, rotate key and try next
                if any(err in error_message for err in ["429", "quota", "rate limit", "503", "unavailable"]):
                    print(f"🚨 [ORCHESTRATOR] Key {self.current_idx} Hit Rate Limit/503! Rotating...")
                    self.current_idx = (self.current_idx + 1) % len(self.providers)
                    attempts += 1
                else:
                    # For non-rate-limit errors (like JSON parsing), just fail to avoid burning all keys
                    print(f"🚨 [ORCHESTRATOR] Unexpected Error on Key {self.current_idx}: {e}")
                    return self._fallback_error("System encountered an unexpected error. Please try again later.")
                    
        return self._fallback_error("System is currently overloaded. Please verify manually.")

    def _fallback_error(self, message: str) -> ModularReport:
        return ModularReport(
            risk_level="Medium",
            detected_language="English",
            specific_analysis=message,
            recommended_action="Do not share personal information until verified.",
            database_findings=None,
            web_search_findings=None
        )
