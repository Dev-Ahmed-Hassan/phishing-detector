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

class WebModularReport(BaseModel):
    risk_level: str
    confidence_score: int           # 0-100
    detected_language: str
    specific_analysis: str
    recommended_action: str
    threat_vectors: list[str]       # e.g., ["Urgency", "Upfront Fee Request"]
    detected_urls: list[str]        # list of URLs found in text/image

class LLMProvider:
    def analyze(self, text: str, media_bytes: bytes = None, mime_type: str = None) -> ModularReport:
        raise NotImplementedError("Subclasses must implement this method")
        
    def analyze_web(self, text: str, media_bytes: bytes = None, mime_type: str = None) -> WebModularReport:
        raise NotImplementedError("Subclasses must implement this method")

class GeminiLLMProvider(LLMProvider):
    def __init__(self, api_key: str):
        self.client = genai.Client(api_key=api_key)
        self.model = "gemini-3.5-flash-lite" 

        self.system_instruction = """
        You are an expert scam and phishing detector specializing in Pakistani job scams.
        
        CRITICAL INSTRUCTIONS:
        1. Analyze the provided job offer or recruiter message carefully.
        2. Language Match: You MUST reply in the EXACT SAME SCRIPT AND LANGUAGE the user used. 
           - If they text in actual Urdu script (e.g. اردو), your `specific_analysis` and `recommended_action` MUST be in Urdu script, NOT Roman Urdu.
           - If they text in Roman Urdu (using English alphabets), reply in Roman Urdu.
           - If they text in English, reply in English.
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

        self.system_instruction_web = """
        You are an expert scam and phishing detector specializing in Pakistani job scams.
        
        CRITICAL INSTRUCTIONS:
        1. Analyze the provided job offer, recruiter message, or uploaded image/audio.
        2. Language Match: You MUST reply in the EXACT SAME SCRIPT AND LANGUAGE the user used.
        3. Be Specific: Do not use generic warnings. Point out exactly which sentence, salary figure, or fee request is suspicious.
        
        [SYSTEM AUTOMATED URL SCAN] HANDLING:
        If you see a section labeled [SYSTEM AUTOMATED URL SCAN] at the bottom of the prompt, it means our backend actively scraped the URLs in the message. 
        - If a domain is newly registered (e.g. less than 1 year old), increase the risk level and confidence score.
        - If the webpage title contradicts the message (e.g. they claim to be Amazon but the title is "Earn Free Crypto"), explicitly mention this in your `specific_analysis`.
        
        Check for:
        - Upfront fees / Registration fees / Processing fees
        - Unrealistic salaries for the described role
        - High-pressure urgency (e.g., "Reply within 10 minutes")
        - Suspicious links or unverifiable company details (cross-reference with the AUTOMATED URL SCAN if present)
        
        Respond ONLY with a JSON object in this exact format, nothing else:
        {
            "risk_level": "High" | "Medium" | "Low",
            "confidence_score": 85, // Integer from 0 to 100
            "detected_language": "English",
            "specific_analysis": "Detailed explanation of what is fishy...",
            "recommended_action": "Actionable next steps...",
            "threat_vectors": ["Urgency", "Unrealistic Salary", "Upfront Fee"], // Array of short string tags
            "detected_urls": ["http://suspicious-link.com"] // Array of any URLs found in the text or image
        }
        """

    def analyze(self, text: str, media_bytes: bytes = None, mime_type: str = None) -> ModularReport:
        # Build contents array. Always include text.
        contents = [text]
        if media_bytes and mime_type:
            contents.append(
                types.Part.from_bytes(data=media_bytes, mime_type=mime_type)
            )

        response = self.client.models.generate_content(
            model=self.model,
            contents=contents,
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

    def analyze_web(self, text: str, media_bytes: bytes = None, mime_type: str = None) -> WebModularReport:
        contents = [text]
        if media_bytes and mime_type:
            contents.append(
                types.Part.from_bytes(data=media_bytes, mime_type=mime_type)
            )

        response = self.client.models.generate_content(
            model=self.model,
            contents=contents,
            config=types.GenerateContentConfig(
                system_instruction=self.system_instruction_web,
                temperature=0.0, # Deterministic setting
                response_mime_type="application/json"
            )
        )
        
        raw_content = response.text.strip()
        if raw_content.startswith("```json"):
            raw_content = raw_content[7:-3].strip()
        elif raw_content.startswith("```"):
            raw_content = raw_content[3:-3].strip()
            
        data = json.loads(raw_content)
        
        return WebModularReport(
            risk_level=data.get("risk_level", "Medium"),
            confidence_score=data.get("confidence_score", 50),
            detected_language=data.get("detected_language", "English"),
            specific_analysis=data.get("specific_analysis", "Could not fully parse reasoning."),
            recommended_action=data.get("recommended_action", "Be careful and verify the source."),
            threat_vectors=data.get("threat_vectors", []),
            detected_urls=data.get("detected_urls", [])
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

    def analyze(self, text: str, media_bytes: bytes = None, mime_type: str = None) -> ModularReport:
        if not self.providers:
            return self._fallback_error("No API keys configured.")

        attempts = 0
        while attempts < len(self.providers):
            provider = self.providers[self.current_idx]
            try:
                return provider.analyze(text, media_bytes, mime_type)
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

    def analyze_web(self, text: str, media_bytes: bytes = None, mime_type: str = None) -> WebModularReport:
        if not self.providers:
            return self._fallback_error_web("No API keys configured.")

        attempts = 0
        while attempts < len(self.providers):
            provider = self.providers[self.current_idx]
            try:
                return provider.analyze_web(text, media_bytes, mime_type)
            except Exception as e:
                error_message = str(e).lower()
                
                if any(err in error_message for err in ["429", "quota", "rate limit", "503", "unavailable"]):
                    print(f"🚨 [ORCHESTRATOR] Key {self.current_idx} Hit Rate Limit/503! Rotating...")
                    self.current_idx = (self.current_idx + 1) % len(self.providers)
                    attempts += 1
                else:
                    print(f"🚨 [ORCHESTRATOR] Unexpected Error on Key {self.current_idx}: {e}")
                    return self._fallback_error_web("System encountered an unexpected error. Please try again later.")
                    
        return self._fallback_error_web("System is currently overloaded. Please verify manually.")

    def _fallback_error_web(self, message: str) -> WebModularReport:
        return WebModularReport(
            risk_level="Medium",
            confidence_score=50,
            detected_language="English",
            specific_analysis=message,
            recommended_action="Do not share personal information until verified.",
            threat_vectors=["Error"],
            detected_urls=[]
        )
