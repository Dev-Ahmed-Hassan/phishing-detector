from typing import List, Optional
from fastapi import FastAPI, Request, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
import httpx
import json
import os
import time

from core.llm_provider import OrchestratorLLMProvider
from core.analyzer_pipeline import AnalyzerPipeline
from core.response_formatter import ResponseFormatter
from core.database import Database
from core.extractor_v2 import ExtractorV2
from core.osint_collector_v2 import OSINTCollectorV2
from core.judge_v2 import JudgeV2
from core.contact_trace_formatter import ContactTraceFormatter

# Vercel looks for an instance specifically named "app"
app = FastAPI()

# The frontend normally reaches us via its own Next.js rewrite proxy (no CORS needed),
# but direct browser calls are allowed as a fallback for long-running V2 scans.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://naukrinigran.vercel.app",
        "https://naukrinigran-git-test-db-feat-ahmed--hassan.vercel.app",
        "https://naukrinigran-7xauq1d97-ahmed-hassan.vercel.app",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

WIREWEB_API_KEY = os.getenv("WIREWEB_API_KEY")
WIREWEB_SESSION_ID = os.getenv("WIREWEB_SESSION_ID")

# Initialize our modular pipeline and DB
db = Database()
llm_provider = OrchestratorLLMProvider()
pipeline = AnalyzerPipeline(llm_provider, db=db)

@app.get("/")
def read_root():
    return {"message": "FastAPI WhatsApp Webhook Server is running (Modular V2)!"}

@app.post("/api/analyze-web")
async def analyze_web(
    text: str = Form(default=""),
    file: UploadFile = File(default=None),
    user_id: str = Form(default="web_user_anonymous")
):
    media_bytes = None
    mime_type = None
    
    if file:
        media_bytes = await file.read()
        mime_type = file.content_type
        
    assessment = pipeline.process_web(
        text=text, 
        media_bytes=media_bytes, 
        mime_type=mime_type
    )
    
    return {
        "status": "success",
        "report": {
            "risk_level": assessment.risk_level,
            "confidence_score": assessment.confidence_score,
            "detected_language": assessment.detected_language,
            "specific_analysis": assessment.specific_analysis,
            "recommended_action": assessment.recommended_action,
            "threat_vectors": assessment.threat_vectors,
            "detected_urls": assessment.detected_urls,
            "digital_footprint": assessment.digital_footprint,
            "investigation_log": assessment.investigation_log,
            "sources": assessment.sources
        }
    }

@app.post("/api/analyze-v2")
async def analyze_web_v2(
    text: str = Form(default=""),
    file: Optional[UploadFile] = File(default=None),
    files: List[UploadFile] = File(default=[]),
    user_id: str = Form(default="web_user_anonymous")
):
    """
    V2 pipeline: ExtractorV2 -> OSINTCollectorV2 -> JudgeV2.
    Long-running (30-90s); requires raised function maxDuration.
    """
    all_files = []
    if file and file.filename:
        all_files.append(file)
    if files:
        for f in files:
            if f and f.filename and f not in all_files:
                all_files.append(f)

    if not text.strip() and not all_files:
        return {"status": "error", "message": "Provide text or an image to analyze."}

    media_bytes = None
    mime_type = None
    if all_files:
        primary_file = all_files[0]
        media_bytes = await primary_file.read()
        mime_type = primary_file.content_type

    timings = {}

    try:
        # Phase 1: Extraction (regex + Gemini multimodal)
        t0 = time.time()
        extraction = ExtractorV2().extract_information(
            text=text, media_bytes=media_bytes, mime_type=mime_type
        )
        timings["extraction_s"] = round(time.time() - t0, 1)

        master = extraction.get("consolidated_master_result", {})
        has_entities = any([
            master.get("organization_name"),
            master.get("all_unique_urls"),
            master.get("all_unique_emails"),
            master.get("all_unique_phones"),
            master.get("unique_verifiable_claims")
        ])
        if not has_entities:
            return {
                "status": "success",
                "report": None,
                "message": "No verifiable entities (company, links, emails, phones) were found in this message.",
                "extracted_entities": {
                    "organization_name": None,
                    "roles": [],
                    "salary_or_fee_claims": None,
                    "urls": [],
                    "emails": [],
                    "phones": []
                },
                "timings": timings
            }

        # Phase 2: OSINT evidence collection (100% Python)
        print(f"[V2] Phase 1 done in {timings['extraction_s']}s. Entity: {master.get('organization_name')}")
        t1 = time.time()
        dossier = OSINTCollectorV2().collect_evidence(extraction)
        timings["osint_collection_s"] = round(time.time() - t1, 1)
        print(f"[V2] Phase 2 done in {timings['osint_collection_s']}s")

        # Phase 3: AI Judgment
        t2 = time.time()
        report = JudgeV2().judge(dossier, original_message=text)
        timings["judgment_s"] = round(time.time() - t2, 1)
        timings["total_s"] = round(time.time() - t0, 1)
        print(f"[V2] Phase 3 done in {timings['judgment_s']}s (total {timings['total_s']}s)")

        contact_traces = ContactTraceFormatter.format(dossier)

        response_payload = {
            "status": "success",
            "report": report,
            "extracted_entities": {
                "organization_name": master.get("organization_name"),
                "roles": master.get("roles", []),
                "salary_or_fee_claims": master.get("salary_or_fee_claims"),
                "urls": master.get("all_unique_urls", []),
                "emails": master.get("all_unique_emails", []),
                "phones": master.get("all_unique_phones", [])
            },
            "contact_traces": contact_traces,
            "timings": timings
        }

        # Save to Supabase and generate unique dossier_id for sharing
        dossier_id = db.save_dossier(response_payload) if db else ""
        if dossier_id:
            response_payload["dossier_id"] = dossier_id

        return response_payload
    except Exception as e:
        print(f"[V2] Pipeline error: {e}")
        return {"status": "error", "message": str(e), "timings": timings}


@app.get("/api/report/{report_id}")
async def get_report(report_id: str):
    if not db:
        return {"status": "error", "message": "Database not initialized"}
    report_json = db.get_dossier_by_id(report_id)
    if report_json:
        return report_json
    return {"status": "error", "message": "Report not found or expired"}


@app.post("/webhook")
async def webhook(request: Request):
    try:
        body = await request.json()
    except Exception:
        return {"status": "error", "message": "Invalid JSON"}

    print("--- Incoming Webhook Event ---")
    print(json.dumps(body, indent=2))
    
    # We always use the anonymous ID for tracking the session
    user_id = body.get("sender") or body.get("chat") or "unknown_user"
    message_text = body.get("text") or body.get("message")
        
    if body.get("fromMe") is True:
        return {"status": "skipped", "reason": "Self message"}
        
    if not message_text:
        return {"status": "ignored", "reason": "No text content"}

    print(f'Processing message from {user_id}: "{message_text}"')
    
    # --- ACTIVATION GATEKEEPER LOGIC ---
    user = db.get_or_create_user(user_id) if db else None
    
    is_registered = False
    recipient_phone = body.get("from") # Default fallback if DB fails
    
    if user:
        recipient_phone = user.get("phone_number")
        is_registered = bool(recipient_phone)
        
    if not is_registered and db:
        # Check if they are trying to activate
        if message_text.strip().startswith("ACTIVATE_SCAM_DETECTOR="):
            real_phone = message_text.split("=")[1].strip()
            db.register_phone_number(user_id, real_phone)
            
            reply_message = "*✅ Success! Your number is now registered.*\n\nPlease re-send any previous scam messages you want me to analyze!"
            recipient_phone = real_phone
        else:
            # Silently log their message and ignore
            db.save_message(user_id, "user", message_text)
            print(f"Silently logged message for unregistered user {user_id}")
            return {"status": "ignored", "reason": "User unregistered. Silently logged."}
    else:
        # User IS registered (or DB is disabled)
        # 1. Run the AI Pipeline with Context
        assessment = pipeline.process(user_id, message_text)
        # 2. Format specifically for WhatsApp
        reply_message = ResponseFormatter.format_whatsapp(assessment)
    
    # If we somehow still don't have a recipient, we can't send a message
    if not recipient_phone:
        print("Error: No recipient phone number available to send reply.")
        return {"status": "error", "reason": "No recipient phone number"}

    # Send the reply back to WireWeb using the REAL phone number
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                'https://app.wireweb.co.in/api/v1/messages',
                json={
                    "sessionId": WIREWEB_SESSION_ID,
                    "to": recipient_phone,
                    "text": reply_message
                },
                headers={
                    "Authorization": f"Bearer {WIREWEB_API_KEY}",
                    "Content-Type": "application/json"
                }
            )
            print(f"Sent reply to {recipient_phone}:", response.text)
            return {"status": "success"}
        except Exception as e:
            print("Error sending message:", str(e))
            return {"status": "error", "message": str(e)}