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
    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        # The new Google GenAI client
        self.client = genai.Client(api_key=api_key)
        self.model = "gemini-3.6-flash" 

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
        try:
            response = self.client.models.generate_content(
                model='gemini-3.6-flash',
                contents=text,
                config=types.GenerateContentConfig(
                    system_instruction=self.system_instruction,
                    temperature=0.2,
                    response_mime_type="application/json"
                )
            )
            
            raw_content = response.text.strip()
            
            # Defensive check: if Gemini accidentally wraps it in markdown, strip it.
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
        except Exception as e:
            error_message = str(e)
            
            # Check for Rate Limiting / Quota exceeded (usually HTTP 429)
            if "429" in error_message or "quota" in error_message.lower() or "rate" in error_message.lower():
                print("🚨 [CRITICAL LOG] GEMINI API RATE LIMIT OR QUOTA REACHED! 🚨")
                print(f"Details: {error_message}")
            else:
                print(f"Gemini API Error: {error_message}")
                
            return ModularReport(
                risk_level="Medium",
                detected_language="English",
                specific_analysis="System is currently overloaded or unavailable. Please verify manually.",
                recommended_action="Do not share personal information until verified.",
                database_findings=None,
                web_search_findings=None
            )
