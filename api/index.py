from fastapi import FastAPI, Request, File, UploadFile, Form
import httpx
import json
import os

from core.llm_provider import OrchestratorLLMProvider
from core.analyzer_pipeline import AnalyzerPipeline
from core.response_formatter import ResponseFormatter
from core.database import Database

# Vercel looks for an instance specifically named "app"
app = FastAPI()

WIREWEB_API_KEY = os.getenv("WIREWEB_API_KEY", "wire_r1QEC8lzmrmhHSIIZ6cyk-G0h9Z7v4Th")
WIREWEB_SESSION_ID = os.getenv("WIREWEB_SESSION_ID", "ws_mqr7bc5o")

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
            "detected_urls": assessment.detected_urls
        }
    }

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