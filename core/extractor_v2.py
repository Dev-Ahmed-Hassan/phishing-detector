import os
import re
import json
from typing import List, Dict, Any, Optional
from google import genai
from google.genai import types
from core.url_scanner import URLScanner

class ExtractorV2:
    """
    Standalone V2 Data Extractor.
    Implements full traceability across input sources:
    1. Pre-AI Regex pass on user_text
    2. AI Multimodal pass on user_text + image
    3. Post-AI Regex pass on image_text (OCR)
    4. Python Master Consolidation & Deduplication
    """
    
    EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    # Pakistani Phone Number Regex (+923XX..., 03XX-..., 03XXXXXXXXX)
    PHONE_REGEX = re.compile(r'(?:\+92[-\s]?3\d{2}|03\d{2})[-\s]?\d{7}\b')

    def __init__(self, api_key: Optional[str] = None):
        self.clients = []
        if api_key:
            self.clients.append(genai.Client(api_key=api_key))
        else:
            for key_name in ["GEMINI_API_KEY", "GEMINI_API_KEY_2", "GEMINI_API_KEY_3", "GEMINI_API"]:
                key = os.getenv(key_name)
                if key and genai:
                    self.clients.append(genai.Client(api_key=key))
            
        self.models_to_try = [
            "gemini-3.5-flash-lite",
            "gemini-3.1-flash-lite",
            "gemini-2.5-flash",
            "gemini-2.0-flash"
        ]

    def extract_information(
        self, 
        text: str = "", 
        media_bytes: Optional[bytes] = None, 
        mime_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Step 1 Traceable & Consolidated Data Extraction:
        """
        clean_user_text = text.strip() if text else ""
        
        # 1. Pre-AI Pass: Run Python Regex directly on user_text
        user_text_urls = URLScanner.extract_urls(clean_user_text) if clean_user_text else []
        user_text_emails = list(set([e.lower() for e in self.EMAIL_REGEX.findall(clean_user_text)])) if clean_user_text else []
        user_text_phones = list(set([p.strip() for p in self.PHONE_REGEX.findall(clean_user_text)])) if clean_user_text else []
        
        user_text_regex = {
            "urls": user_text_urls,
            "emails": user_text_emails,
            "phones": user_text_phones
        }
        
        # 2. AI Multimodal Pass: Pass text + media to Gemini
        raw_ai_output = self._run_ai_extraction(clean_user_text, media_bytes, mime_type)
        
        # 3. Post-AI Pass: Run Python Regex on AI OCR image_text
        ocr_text = raw_ai_output.get("extracted_text", "")
        clean_ocr_text = ocr_text.strip() if ocr_text else ""
        
        image_text_urls = URLScanner.extract_urls(clean_ocr_text) if clean_ocr_text else []
        image_text_emails = list(set([e.lower() for e in self.EMAIL_REGEX.findall(clean_ocr_text)])) if clean_ocr_text else []
        image_text_phones = list(set([p.strip() for p in self.PHONE_REGEX.findall(clean_ocr_text)])) if clean_ocr_text else []
        
        image_text_regex = {
            "urls": image_text_urls,
            "emails": image_text_emails,
            "phones": image_text_phones
        }
        
        # 4. Master Consolidation & Deduplication (Python Side)
        ai_entities = raw_ai_output.get("entities", {})
        ai_urls = raw_ai_output.get("urls", [])
        ai_emails = ai_entities.get("emails", [])
        ai_phones = ai_entities.get("phones", [])
        
        all_unique_urls = list(set([u for u in (user_text_urls + image_text_urls + ai_urls) if u]))
        all_unique_emails = list(set([e.lower() for e in (user_text_emails + image_text_emails + ai_emails) if e]))
        all_unique_phones = list(set([p.strip() for p in (user_text_phones + image_text_phones + ai_phones) if p]))
        
        org = ai_entities.get("organization_name")
        if not org or org.lower() in ["unknown", "none", "n/a", "null"]:
            org = None
            
        consolidated_master_result = {
            "organization_name": org,
            "roles": ai_entities.get("roles", []),
            "salary_or_fee_claims": ai_entities.get("salary_or_fee_claims"),
            "all_unique_urls": all_unique_urls,
            "all_unique_emails": all_unique_emails,
            "all_unique_phones": all_unique_phones,
            "unique_verifiable_claims": raw_ai_output.get("verifiable_claims", [])
        }
        
        return {
            "inputs": {
                "user_text": clean_user_text,
                "image_text": clean_ocr_text
            },
            "extraction_breakdown": {
                "user_text_regex": user_text_regex,
                "image_text_regex": image_text_regex,
                "raw_ai_output": raw_ai_output
            },
            "consolidated_master_result": consolidated_master_result
        }

    def _run_ai_extraction(
        self, 
        text: str, 
        media_bytes: Optional[bytes] = None, 
        mime_type: Optional[str] = None
    ) -> Dict[str, Any]:
        if not self.clients:
            return {"error": "Gemini client not initialized. Check API Key.", "extracted_text": "", "entities": {}, "urls": [], "verifiable_claims": []}

        prompt = """
        You are a Pure Data Extraction, Audio Transcription, and OCR Agent specializing in job offers, recruitment flyers, voice messages, and scam evidence.
        
        YOUR TASKS:
        1. OCR / Audio Transcription / Text Extraction: Transcribe ALL visible text from images/documents OR spoken words from audio files accurately. Do not alter or translate the original content.
        2. Entity Extraction: Extract raw entities mentioned without judging or making risk decisions.
           - organization_name: Exact name of the company/organization, or null if none is mentioned.
           - emails: List of contact emails.
           - phones: List of contact phone numbers.
           - roles: Job titles or internship roles offered.
           - salary_or_fee_claims: Exact mentions of salary, stipend, or fee amounts.
        3. URL Extraction: Extract any web links, website domains, or social media handles printed/written.
        4. Verifiable Claims: Extract key factual claims made by this offering.
           CRITICAL RULE FOR CLAIMS: The `search_query` field MUST ALWAYS BE WRITTEN IN CLEAN, PROFESSIONAL ENGLISH, regardless of whether the original text is in Roman Urdu, Urdu script, or English!
        
        Respond ONLY with a JSON object in this exact format:
        {
          "extracted_text": "Full transcribed text from image or message...",
          "entities": {
             "organization_name": "Name of Company or null",
             "emails": ["email1@domain.com"],
             "phones": ["+923001234567"],
             "roles": ["Web Developer Intern"],
             "salary_or_fee_claims": "e.g. Free Internship / Rs. 50,000"
          },
          "urls": ["http://example.com"],
          "verifiable_claims": [
             {
               "claim": "Direct or indirect claim to verify",
               "search_query": "Clean English search query to verify this claim"
             }
          ]
        }
        """

        contents = []
        if text:
            contents.append(f"USER TEXT INPUT:\n{text}")
        if media_bytes and mime_type:
            contents.append(types.Part.from_bytes(data=media_bytes, mime_type=mime_type))
            
        if not contents:
            return {"extracted_text": "", "entities": {}, "urls": [], "verifiable_claims": []}

        last_error = None
        for client in self.clients:
            for model_name in self.models_to_try:
                try:
                    response = client.models.generate_content(
                        model=model_name,
                        contents=contents,
                        config=types.GenerateContentConfig(
                            system_instruction=prompt,
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
                except Exception as e:
                    last_error = e
                    print(f"ExtractorV2 AI Error ({model_name}): {e}")
                    continue

        return {"error": str(last_error), "extracted_text": "", "entities": {}, "urls": [], "verifiable_claims": []}
