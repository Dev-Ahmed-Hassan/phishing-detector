from typing import List, Optional, Dict, Any
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
from core.translator_v2 import ReportTranslatorV2

# Vercel looks for an instance specifically named "app"
app = FastAPI()

# The frontend normally reaches us via its own Next.js rewrite proxy (no CORS needed),
# but direct browser calls are allowed as a fallback for long-running V2 scans.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://scamless.vercel.app",
        "https://scamless-ai.vercel.app",
        "https://scamless-web.vercel.app",
        "https://naukrinigran.vercel.app",
        "https://naukrinigran-git-public-report-feat-ahmed--hassan.vercel.app",
        "https://naukrinigran-git-test-db-feat-ahmed--hassan.vercel.app",
        "https://naukrinigran-7xauq1d97-ahmed-hassan.vercel.app",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "*"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

WIREWEB_API_KEY = os.getenv("WIREWEB_API_KEY")
WIREWEB_SESSION_ID = os.getenv("WIREWEB_SESSION_ID")

ADMIN_SECRET_KEY = os.getenv("ADMIN_SECRET_KEY", "naukri_nigran_admin_2026")

# Initialize our modular pipeline and DB
db = Database()
llm_provider = OrchestratorLLMProvider()
pipeline = AnalyzerPipeline(llm_provider, db=db)


@app.post("/api/submit-community-report")
async def submit_community_report(payload: dict):
    if not db:
        return {"status": "error", "message": "Database unavailable"}
    org_name = payload.get("org_name")
    proof_text = payload.get("proof_text")

    if not org_name or not proof_text:
        return {"status": "error", "message": "Organization name and proof statement are required."}

    res = db.submit_community_report(payload)
    return res


@app.get("/api/admin/pending-reports")
async def get_pending_reports(admin_key: str):
    if admin_key != ADMIN_SECRET_KEY:
        return {"status": "error", "message": "Unauthorized Admin Key"}
    if not db:
        return []
    return db.get_pending_community_reports()


@app.post("/api/admin/verify-report")
async def verify_report(payload: dict):
    admin_key = payload.get("admin_key")
    report_id = payload.get("report_id")
    action = payload.get("action", "approve")

    if admin_key != ADMIN_SECRET_KEY:
        return {"status": "error", "message": "Unauthorized Admin Key"}
    if not db or not report_id:
        return {"status": "error", "message": "Invalid report ID"}

    res = db.verify_community_report(int(report_id), action=action, edited_data=payload)
    return res

@app.get("/")
def read_root():
    return {"message": "FastAPI WhatsApp Webhook Server is running (Modular V2)!"}

from core.translator_v2 import ReportTranslatorV2
translator = ReportTranslatorV2()

@app.post("/api/openwa-test-webhook")
async def openwa_test_webhook(request: Request):
    """
    Test endpoint for OpenWA WhatsApp Webhook.
    Intercepts incoming text, images, and audio without triggering the heavy AI pipeline,
    and sends an instant echo reply back to the sender's WhatsApp number.
    """
    try:
        data = await request.json()
    except Exception:
        return {"status": "error", "message": "Invalid JSON"}

    print("--- OpenWA Webhook Intercepted ---")
    print(json.dumps(data, indent=2)[:500])

    msg_data = data.get("payload") or data.get("data") or data
    if isinstance(msg_data, str):
        return {"status": "ok"}

    from_me = msg_data.get("fromMe", False)
    if from_me:
        return {"status": "ignored", "reason": "Self message"}

    chat_id = msg_data.get("from") or msg_data.get("chatId")
    if not chat_id:
        return {"status": "ignored", "reason": "No sender chatId found"}

    text = msg_data.get("body", "")
    msg_type = msg_data.get("type", "chat")
    has_media = msg_data.get("hasMedia", False)
    session_id = data.get("sessionId") or os.getenv("OPENWA_SESSION_ID", "default")

    media_note = " 📷 Image attached" if msg_type == "image" or has_media else ""
    if msg_type == "audio":
        media_note = " 🎤 Audio voice note attached"

    reply_text = (
        f"🤖 *[ScamLess Gateway Test Mode]*\n\n"
        f"✅ Received your WhatsApp message!\n"
        f"• *Sender*: `{chat_id}`\n"
        f"• *Type*: {msg_type}{media_note}\n"
        f"• *Text*: \"{text[:200] if text else '(No text caption)'}\"\n\n"
        f"⚡ *Status*: Webhook & Auto-Reply pipeline working 100% end-to-end!"
    )

    openwa_base = os.getenv("OPENWA_GATEWAY_URL", "https://openwa-production-731b.up.railway.app").rstrip("/")
    api_key = os.getenv("OPENWA_API_KEY", "")

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    send_url = f"{openwa_base}/api/sessions/{session_id}/messages/send-text"

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.post(
                send_url,
                json={"chatId": chat_id, "text": reply_text},
                headers=headers
            )
            print(f"OpenWA Test Reply Sent ({resp.status_code}): {resp.text}")
            return {"status": "success", "openwa_status": resp.status_code, "chatId": chat_id}
        except Exception as e:
            print("Error calling OpenWA send-text:", str(e))
            return {"status": "error", "message": str(e)}


@app.post("/api/translate-report")
async def translate_report_endpoint(payload: dict):
    if not translator:
        return {"status": "error", "message": "Translator uninitialized"}
    return translator.translate_report(payload)

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


@app.post("/api/translate-report")
async def translate_report_endpoint(payload: dict):
    summary = payload.get("summary", "")
    key_findings = payload.get("key_findings", [])
    red_flags = payload.get("red_flags", [])
    recommended_actions = payload.get("recommended_actions", [])

    if not summary and not key_findings and not red_flags:
        return {"status": "error", "message": "Nothing to translate"}

    translator = ReportTranslatorV2()
    result = translator.translate_report(
        summary=summary,
        key_findings=key_findings,
        red_flags=red_flags,
        recommended_actions=recommended_actions
    )
    return result


def _background_save(payload: dict, dossier: dict, report: dict, custom_id: str):
    if not db:
        return
    try:
        # Pre-generate 3-language translations for instant web app tab switching
        if isinstance(report, dict) and translator:
            try:
                user_report = report.get("user_facing_report", {})
                summary = user_report.get("summary_paragraph", "")
                actions = user_report.get("what_you_should_do", [])
                key_findings = [f.get("claim", "") for f in report.get("verified_facts", []) if f.get("claim")]
                red_flags = [f.get("flag", "") for f in report.get("red_flags", []) if f.get("flag")]

                tr_res = translator.translate_report(
                    summary=summary,
                    key_findings=key_findings,
                    red_flags=red_flags,
                    recommended_actions=actions
                )
                if tr_res.get("status") == "success":
                    payload["translations"] = tr_res.get("translations")
            except Exception as tr_err:
                print(f"[Background Pre-Translation Error]: {tr_err}")

        # 1. Save main dossier to Supabase (includes 3-language translations)
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


import asyncio

# In-Memory Message Buffering for Rapid Multi-Message Aggregation
USER_MESSAGE_BUFFERS: Dict[str, List[Dict[str, Any]]] = {}
USER_BUFFER_TASKS: Dict[str, asyncio.Task] = {}
ACKNOWLEDGED_CHATS: set = set()


async def _flush_buffer_and_process_v2(chat_id: str, session_id: str):
    """
    Timer Callback: Wait 5 seconds after the first message arrives.
    Combines all texts, photos, and audio notes sent within those 5 seconds into ONE unified AI scan!
    """
    await asyncio.sleep(5.0)  # 5-second aggregation window

    buffer_items = USER_MESSAGE_BUFFERS.pop(chat_id, [])
    USER_BUFFER_TASKS.pop(chat_id, None)
    ACKNOWLEDGED_CHATS.discard(chat_id)

    if not buffer_items:
        return

    # Combine text snippets from all messages sent in the 5-second window
    combined_texts = [item["text"].strip() for item in buffer_items if item.get("text") and item["text"].strip()]
    full_text = "\n\n".join(combined_texts)

    # Pick the primary media item (only if real media was attached)
    primary_media_item = None
    for item in buffer_items:
        if item.get("has_media") is True and item.get("msg_type") in ["image", "audio", "ptt", "document"]:
            primary_media_item = item
            break

    msg_type = primary_media_item["msg_type"] if primary_media_item else "chat"
    has_media = primary_media_item["has_media"] if primary_media_item else False
    message_id = primary_media_item["message_id"] if primary_media_item else None

    # Retrieve timestamp of the initial message in this batch
    first_time = buffer_items[0].get("timestamp") or time.strftime("%H:%M:%S")

    # Execute full V2 pipeline worker with aggregated inputs
    await _process_openwa_full_v2_and_reply(
        chat_id=chat_id,
        text=full_text,
        msg_type=msg_type,
        has_media=has_media,
        message_id=message_id,
        session_id=session_id,
        received_at=first_time
    )


async def _process_openwa_full_v2_and_reply(
    chat_id: str,
    text: str,
    msg_type: str,
    has_media: bool,
    message_id: Optional[str],
    session_id: str,
    received_at: str = ""
):
    """
    Asynchronous Full V2 Pipeline Worker:
    1. Downloads image/audio binary from OpenWA if media is present.
    2. Runs ExtractorV2 (OCR + Audio Transcription + Regex).
    3. Runs OSINTCollectorV2 (Web Search + WHOIS + Supabase Database).
    4. Runs JudgeV2 (Deterministic Scoring + Multi-model LLM Verdict in user's input language).
    5. Saves dossier to Supabase and sends an emoji-free verdict report with full web report link.
    """
    if not received_at:
        received_at = time.strftime("%H:%M:%S")

    # Create short query preview for clear message tracking in replies
    clean_snippet = text.strip().replace("\n", " ")
    if len(clean_snippet) > 35:
        query_snippet = clean_snippet[:35] + "..."
    elif clean_snippet:
        query_snippet = clean_snippet
    else:
        query_snippet = "[Photo / Audio Flyer]"

    openwa_base = os.getenv("OPENWA_GATEWAY_URL", "https://openwa-production-731b.up.railway.app").rstrip("/")
    api_key = os.getenv("OPENWA_API_KEY", "")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    media_bytes = None
    mime_type = None

    # Only attempt media download if actual media attachment is present
    if has_media and msg_type in ["image", "audio", "ptt", "document"] and message_id:
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                media_url = f"{openwa_base}/api/sessions/{session_id}/messages/{message_id}/media"
                resp = await client.get(media_url, headers=headers)
                if resp.status_code == 200:
                    media_bytes = resp.content
                    mime_type = resp.headers.get("content-type", "image/jpeg" if msg_type == "image" else "audio/ogg")
                    print(f"[OpenWA] Downloaded media bytes ({len(media_bytes)} bytes, mime={mime_type})")
            except Exception as e:
                print(f"[OpenWA] Error fetching media for {message_id}: {e}")

    try:
        # Phase 1: ExtractorV2
        extraction = ExtractorV2().extract_information(
            text=text, media_bytes=media_bytes, mime_type=mime_type
        )
        master = extraction.get("consolidated_master_result", {})
        has_entities = any([
            master.get("organization_name"),
            master.get("all_unique_urls"),
            master.get("all_unique_emails"),
            master.get("all_unique_phones"),
            master.get("unique_verifiable_claims")
        ])

        # If user typed a company name query (e.g., "Ubexi"), use text input as target organization
        if not has_entities and text and len(text.strip()) >= 3:
            master["organization_name"] = text.strip()
            has_entities = True

        if not has_entities:
            reply_text = (
                f"*SCAMLESS ANALYSIS REPORT*\n"
                f"----------------------------------------\n"
                f"*Original Query*: \"{query_snippet}\"\n"
                f"*Received At*: {received_at}\n\n"
                f"No verifiable company names, website URLs, contact emails, or phone numbers were detected in your input.\n\n"
                f"Tip: Send an offer letter, recruiter text, job flyer image, or audio note containing company contact details to perform a full OSINT investigation!"
            )
        else:
            # Phase 2: OSINTCollectorV2
            dossier = OSINTCollectorV2().collect_evidence(extraction)
            # Phase 3: JudgeV2 (Outputs summary & actions in user's prompt language)
            report = JudgeV2().judge(dossier, original_message=text)

            exec_sum = report.get("executive_summary", {})
            verdict = exec_sum.get("verdict", "inconclusive").upper()
            conf = exec_sum.get("confidence_score", 50)

            user_report = report.get("user_facing_report", {})
            summary = user_report.get("summary_paragraph", "")
            actions = user_report.get("what_you_should_do", [])
            target_entity = master.get("organization_name") or "Unknown Entity"

            actions_str = "\n".join([f"- {a}" for a in actions[:3]]) if actions else "- Verify company credentials before making any payments."

            # Generate permanent dossier ID and save to Supabase DB for web link
            dossier_id = f"rep_{secrets.token_hex(6)}"
            web_domain = os.getenv("WEB_APP_URL", "https://scamless.vercel.app").rstrip("/")
            report_link = f"{web_domain}/report/{dossier_id}"

            response_payload = {
                "status": "success",
                "report": report,
                "extracted_entities": master,
                "dossier_id": dossier_id
            }

            if db:
                try:
                    _background_save(response_payload, dossier, report, dossier_id)
                except Exception as db_err:
                    print(f"[OpenWA] DB save error: {db_err}")

            reply_text = (
                f"*SCAMLESS FORENSIC REPORT*\n"
                f"----------------------------------------\n"
                f"*Original Query*: \"{query_snippet}\"\n"
                f"*Received At*: {received_at}\n"
                f"*Target Entity*: {target_entity}\n"
                f"*Verdict*: {verdict}\n"
                f"*Trust Score*: {conf}/100\n\n"
                f"*SUMMARY*:\n{summary}\n\n"
                f"*RECOMMENDED ACTIONS*:\n{actions_str}\n\n"
                f"*Full Detailed Report Link*:\n{report_link}"
            )

    except Exception as err:
        print(f"[OpenWA V2 Pipeline Error]: {err}")
        reply_text = (
            f"*SCAMLESS ANALYSIS REPORT*\n"
            f"----------------------------------------\n"
            f"*Original Query*: \"{query_snippet}\"\n"
            f"*Received At*: {received_at}\n\n"
            f"Analysis Error: Could not complete OSINT verification. Please try re-sending the message or flyer."
        )

    # Post final report to OpenWA
    send_url = f"{openwa_base}/api/sessions/{session_id}/messages/send-text"
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            await client.post(
                send_url,
                json={"chatId": chat_id, "text": reply_text},
                headers=headers
            )
            print(f"[OpenWA] Final V2 report sent successfully to {chat_id}")
        except Exception as e:
            print(f"[OpenWA] Failed to send final report to {chat_id}: {e}")


@app.post("/webhook")
@app.post("/api/webhook")
async def webhook(request: Request, background_tasks: BackgroundTasks):
    """
    Main Webhook endpoint supporting OpenWA (and fallback legacy integrations).
    Handles text, images, and audio voice notes end-to-end with 5-second aggregation buffer.
    """
    try:
        body = await request.json()
    except Exception:
        return {"status": "error", "message": "Invalid JSON"}

    print("--- Incoming Webhook Event ---")
    print(json.dumps(body, indent=2)[:500])

    is_openwa = ("sessionId" in body) or ("event" in body) or ("payload" in body and isinstance(body["payload"], dict) and "from" in body["payload"])

    if is_openwa:
        msg_data = body.get("payload") or body.get("data") or body
        if isinstance(msg_data, str):
            return {"status": "ok"}

        from_me = msg_data.get("fromMe", False)
        if from_me:
            return {"status": "skipped", "reason": "Self message"}

        chat_id = msg_data.get("from") or msg_data.get("chatId")
        if not chat_id:
            return {"status": "ignored", "reason": "No sender chatId found"}

        text = msg_data.get("body", "")
        msg_type = msg_data.get("type", "chat")
        has_media = msg_data.get("hasMedia", False)
        message_id = msg_data.get("id") or msg_data.get("_serialized")
        session_id = body.get("sessionId") or os.getenv("OPENWA_SESSION_ID", "default")

        openwa_base = os.getenv("OPENWA_GATEWAY_URL", "https://openwa-production-731b.up.railway.app").rstrip("/")
        api_key = os.getenv("OPENWA_API_KEY", "")

        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["X-API-Key"] = api_key

        # PRODUCTION TEST CHECK: If message is exactly "test-text", bypass AI pipeline completely
        if text.strip().lower() == "test-text":
            test_reply = (
                f"*ScamLess Production Test Check*\n\n"
                f"Instant Recognition Successful!\n"
                f"- Sender: {chat_id}\n"
                f"- Status: OpenWA Webhook -> Vercel Backend -> WhatsApp Reply working 100%!\n\n"
                f"(AI Pipeline was bypassed for this test command)"
            )
            send_url = f"{openwa_base}/api/sessions/{session_id}/messages/send-text"
            async with httpx.AsyncClient(timeout=10.0) as client:
                try:
                    resp = await client.post(
                        send_url,
                        json={"chatId": chat_id, "text": test_reply},
                        headers=headers
                    )
                    print(f"Sent production test-text reply ({resp.status_code}): {resp.text}")
                    return {"status": "success", "mode": "production_test_check", "chatId": chat_id}
                except Exception as e:
                    print("Error sending test-text reply:", str(e))
                    return {"status": "error", "message": str(e)}

        # Format timestamp from message payload or current server time
        raw_ts = msg_data.get("timestamp") or body.get("timestamp")
        if isinstance(raw_ts, (int, float)):
            ts_sec = raw_ts / 1000.0 if raw_ts > 1e11 else float(raw_ts)
            rec_time_str = time.strftime("%H:%M:%S", time.localtime(ts_sec))
        elif isinstance(raw_ts, str) and "T" in raw_ts:
            rec_time_str = raw_ts.split("T")[1].split(".")[0]
        else:
            rec_time_str = time.strftime("%H:%M:%S")

        # Buffer message for 5-second aggregation window
        if chat_id not in USER_MESSAGE_BUFFERS:
            USER_MESSAGE_BUFFERS[chat_id] = []

        USER_MESSAGE_BUFFERS[chat_id].append({
            "text": text,
            "msg_type": msg_type,
            "has_media": has_media,
            "message_id": message_id,
            "timestamp": rec_time_str
        })

        # Send instant receipt acknowledgement to WhatsApp user ONCE per aggregation window (No Emojis)
        if chat_id not in ACKNOWLEDGED_CHATS:
            ACKNOWLEDGED_CHATS.add(chat_id)
            ack_text = (
                "*ScamLess AI Analysis Initiated...*\n\n"
                "We have received your WhatsApp input. Running OCR, transcribing media, and verifying company OSINT footprint. Please wait 15-30 seconds for your full forensic report."
            )
            send_url = f"{openwa_base}/api/sessions/{session_id}/messages/send-text"
            async with httpx.AsyncClient(timeout=10.0) as client:
                try:
                    await client.post(
                        send_url,
                        json={"chatId": chat_id, "text": ack_text},
                        headers=headers
                    )
                except Exception as e:
                    print(f"[OpenWA] Error sending initial ack: {e}")

        # Start 5-second timer task if not already running for this user
        if chat_id not in USER_BUFFER_TASKS:
            USER_BUFFER_TASKS[chat_id] = asyncio.create_task(
                _flush_buffer_and_process_v2(chat_id, session_id)
            )

        return {"status": "buffered", "session": session_id, "chatId": chat_id}

    # Legacy WireWeb fallback path
    user_id = body.get("sender") or body.get("chat") or "unknown_user"
    message_text = body.get("text") or body.get("message")
        
    if body.get("fromMe") is True:
        return {"status": "skipped", "reason": "Self message"}
        
    if not message_text:
        return {"status": "ignored", "reason": "No text content"}

    print(f'Processing legacy message from {user_id}: "{message_text}"')
    recipient_phone = body.get("from") or user_id
    
    assessment = pipeline.process(user_id, message_text)
    reply_message = ResponseFormatter.format_whatsapp(assessment)

    if not recipient_phone or not WIREWEB_API_KEY:
        print("Error: No recipient phone or WireWeb key available.")
        return {"status": "error", "reason": "No recipient phone or WireWeb key"}

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
            print(f"Sent legacy reply to {recipient_phone}:", response.text)
            return {"status": "success"}
        except Exception as e:
            print("Error sending legacy message:", str(e))
            return {"status": "error", "message": str(e)}