from typing import List, Optional
from fastapi import FastAPI, Request, File, UploadFile, Form, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
import httpx
import json
import os
import secrets
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
    background_tasks: BackgroundTasks,
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

        dossier_id = f"rep_{secrets.token_hex(6)}"

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
            "timings": timings,
            "dossier_id": dossier_id
        }

        # Non-blocking background save of dossier permalink and evidence cache
        if db:
            background_tasks.add_task(_background_save, response_payload, dossier, report, dossier_id)

        return response_payload
    except Exception as e:
        print(f"[V2] Pipeline error: {e}")
        return {"status": "error", "message": str(e), "timings": timings}


def _background_save(payload: dict, dossier: dict, report: dict, custom_id: str):
    if not db:
        return
    try:
        # 1. Save main dossier to Supabase
        db.save_dossier(payload, custom_id=custom_id)

        # 2. Extract Gemini-verified evidence items
        verified_items = []
        if isinstance(report, dict):
            # Red flags
            for f in report.get("red_flags", []):
                if f.get("source_url"):
                    verified_items.append({
                        "url": f["source_url"],
                        "title": f.get("flag", "Red Flag Evidence"),
                        "snippet": f.get("snippet_quote", ""),
                        "category": "community_scam",
                        "source_type": f.get("source_type", "web")
                    })
            # Verified facts
            for v in report.get("verified_facts", []):
                if v.get("source_url"):
                    verified_items.append({
                        "url": v["source_url"],
                        "title": v.get("claim", "Verified Fact Evidence"),
                        "snippet": v.get("snippet_quote", ""),
                        "category": "verified_fact",
                        "source_type": v.get("source_type", "web")
                    })
            # Links of interest
            links_dict = report.get("links_of_interest", {})
            if isinstance(links_dict, dict):
                for cat, link_list in links_dict.items():
                    if isinstance(link_list, list):
                        for l in link_list:
                            if isinstance(l, dict) and l.get("url"):
                                verified_items.append({
                                    "url": l["url"],
                                    "title": l.get("title", "Link of Interest"),
                                    "snippet": l.get("explanation", ""),
                                    "category": cat,
                                    "source_type": "web"
                                })

        org_name = dossier.get("target_entity_name")
        if org_name and verified_items:
            db.save_evidence_cache(org_name, verified_items)
    except Exception as err:
        print(f"Background Save Exception: {err}")


@app.get("/api/report/{report_id}")
async def get_report(report_id: str):
    if not db:
        return {"status": "error", "message": "Database not initialized"}
    report_json = db.get_dossier_by_id(report_id)
    if report_json:
        return report_json
    return {"status": "error", "message": "Report not found or expired"}


# In-Memory Message Buffers for WhatsApp Debouncing
_whatsapp_buffers = {}
_whatsapp_buffer_lock = asyncio.Lock()


async def _send_wireweb_message(recipient_phone: str, text: str):
    """Helper to dispatch WhatsApp message via WireWeb API."""
    if not WIREWEB_API_KEY or not WIREWEB_SESSION_ID:
        print("WireWeb Notice: Missing WIREWEB_API_KEY or WIREWEB_SESSION_ID environment variables.")
        return
    async with httpx.AsyncClient() as client:
        try:
            res = await client.post(
                'https://app.wireweb.co.in/api/v1/messages',
                json={
                    "sessionId": WIREWEB_SESSION_ID,
                    "to": recipient_phone,
                    "text": text
                },
                headers={
                    "Authorization": f"Bearer {WIREWEB_API_KEY}",
                    "Content-Type": "application/json"
                },
                timeout=10.0
            )
            print(f"[WhatsApp] Reply sent to {recipient_phone}:", res.status_code)
        except Exception as e:
            print(f"[WhatsApp] Send error to {recipient_phone}: {e}")


async def _process_debounced_whatsapp(user_id: str):
    """Waits 2.5s for rapid consecutive messages, then runs V2 OSINT pipeline."""
    try:
        await asyncio.sleep(2.5)
    except asyncio.CancelledError:
        return

    async with _whatsapp_buffer_lock:
        buf = _whatsapp_buffers.pop(user_id, None)

    if not buf or not buf.get("texts"):
        return

    full_text = "\n\n".join(buf["texts"])
    recipient_phone = buf.get("recipient_phone")

    if not recipient_phone:
        print(f"[WhatsApp] Error: No recipient phone for user {user_id}")
        return

    print(f"[WhatsApp V2] Executing debounced V2 scan for {user_id} ({len(buf['texts'])} messages concatenated)")

    # Send initial acknowledgment message to user
    await _send_wireweb_message(
        recipient_phone,
        "⏳ *Naukri Nigran Investigation Started*\n\nProcessing your job offer through our V2 OSINT Search Engine. Please hold on..."
    )

    try:
        # Phase 1: Extraction
        t0 = time.time()
        extraction = ExtractorV2().extract_information(text=full_text)

        # Phase 2: OSINT Evidence Collection
        dossier = OSINTCollectorV2().collect_evidence(extraction)

        # Phase 3: AI Judgment
        report = JudgeV2().judge(dossier, original_message=full_text)

        contact_traces = ContactTraceFormatter.format(dossier)
        dossier_id = f"rep_{secrets.token_hex(6)}"

        response_payload = {
            "status": "success",
            "report": report,
            "extracted_entities": {
                "organization_name": extraction.get("consolidated_master_result", {}).get("organization_name"),
                "roles": extraction.get("consolidated_master_result", {}).get("roles", []),
                "salary_or_fee_claims": extraction.get("consolidated_master_result", {}).get("salary_or_fee_claims"),
                "urls": extraction.get("consolidated_master_result", {}).get("all_unique_urls", []),
                "emails": extraction.get("consolidated_master_result", {}).get("all_unique_emails", []),
                "phones": extraction.get("consolidated_master_result", {}).get("all_unique_phones", [])
            },
            "contact_traces": contact_traces,
            "dossier_id": dossier_id
        }

        # Background save of dossier permalink and evidence cache
        if db:
            _background_save(response_payload, dossier, report, dossier_id)

        # Format V2 WhatsApp reply
        reply_msg = ResponseFormatter.format_whatsapp_v2(response_payload, dossier_id=dossier_id)

        # Dispatch reply to WhatsApp user
        await _send_wireweb_message(recipient_phone, reply_msg)
    except Exception as err:
        print(f"[WhatsApp V2] Execution Exception for {user_id}: {err}")
        err_msg = "⚠️ *Analysis Error*\n\nUnable to complete automated OSINT search for this offer. Please try again or scan directly on our website:\nhttps://naukrinigran.vercel.app"
        await _send_wireweb_message(recipient_phone, err_msg)


@app.post("/webhook")
async def webhook(request: Request):
    try:
        body = await request.json()
    except Exception:
        return {"status": "error", "message": "Invalid JSON"}

    if body.get("fromMe") is True:
        return {"status": "skipped", "reason": "Self message"}

    user_id = body.get("sender") or body.get("chat") or "unknown_user"
    message_text = body.get("text") or body.get("message") or ""

    if not message_text.strip():
        return {"status": "ignored", "reason": "No text content"}

    print(f'Incoming WhatsApp message from {user_id}: "{message_text[:80]}..."')

    # --- ACTIVATION GATEKEEPER ---
    user = db.get_or_create_user(user_id) if db else None
    recipient_phone = body.get("from")
    if user:
        recipient_phone = user.get("phone_number") or recipient_phone

    clean_text = message_text.strip()

    # Check activation triggers (e.g. ACTIVATE_0340320... or ACTIVATE_SCAM_DETECTOR=0340320...)
    if clean_text.startswith("ACTIVATE_"):
        real_phone = clean_text.replace("ACTIVATE_SCAM_DETECTOR=", "").replace("ACTIVATE_", "").strip()
        if db:
            db.register_phone_number(user_id, real_phone)
        recipient_phone = real_phone or recipient_phone

        welcome_msg = (
            "✅ *ACCOUNT ACTIVATED / اکاؤنٹ کی توثیق ہو گئی*\n\n"
            "Welcome to Naukri Nigran! Forward any suspicious job text message here for instant AI verification.\n\n"
            "⚠️ *NOTE:* This WhatsApp channel currently processes TEXT job offers. "
            "For flyer images or audio files, please scan directly on our website:\n"
            "👉 https://naukrinigran.vercel.app"
        )
        if recipient_phone:
            await _send_wireweb_message(recipient_phone, welcome_msg)
        return {"status": "activated", "phone": recipient_phone}

    if not recipient_phone and db:
        db.save_message(user_id, "user", message_text)
        return {"status": "ignored", "reason": "User unregistered. Silently logged."}

    # --- DEBOUNCE MESSAGE BUFFERING ---
    async with _whatsapp_buffer_lock:
        if user_id not in _whatsapp_buffers:
            _whatsapp_buffers[user_id] = {
                "texts": [],
                "task": None,
                "recipient_phone": recipient_phone
            }
        else:
            # Cancel prior task if user sends another message rapidly
            old_task = _whatsapp_buffers[user_id].get("task")
            if old_task and not old_task.done():
                old_task.cancel()

        _whatsapp_buffers[user_id]["texts"].append(clean_text)
        _whatsapp_buffers[user_id]["recipient_phone"] = recipient_phone or _whatsapp_buffers[user_id]["recipient_phone"]

        # Launch 2.5s debounce task
        new_task = asyncio.create_task(_process_debounced_whatsapp(user_id))
        _whatsapp_buffers[user_id]["task"] = new_task

    return {"status": "buffered", "user_id": user_id, "pending_count": len(_whatsapp_buffers[user_id]["texts"])}