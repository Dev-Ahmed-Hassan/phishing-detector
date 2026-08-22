from fastapi import FastAPI, Request
import httpx
import json
import os

from core.llm_provider import GeminiLLMProvider
from core.analyzer_pipeline import AnalyzerPipeline
from core.response_formatter import ResponseFormatter

# Vercel looks for an instance specifically named "app"
app = FastAPI()

WIREWEB_API_KEY = os.getenv("WIREWEB_API_KEY", "wire_r1QEC8lzmrmhHSIIZ6cyk-G0h9Z7v4Th")
WIREWEB_SESSION_ID = os.getenv("WIREWEB_SESSION_ID", "ws_mqr7bc5o")

# Initialize our modular pipeline
llm_provider = GeminiLLMProvider()
pipeline = AnalyzerPipeline(llm_provider)

@app.get("/")
def read_root():
    return {"message": "FastAPI WhatsApp Webhook Server is running (Modular V2)!"}

@app.post("/webhook")
async def webhook(request: Request):
    try:
        body = await request.json()
    except Exception:
        return {"status": "error", "message": "Invalid JSON"}

    print("--- Incoming Webhook Event ---")
    
    recipient = body.get("chat") or body.get("sender") or body.get("from")
    message_text = body.get("text") or body.get("message")
    
    # Bypass routing bug for specific phone
    if recipient and "219056804204600" in recipient:
        recipient = "923350309309"
        
    if not recipient or not message_text:
        return {"status": "skipped", "reason": "Empty text/recipient"}
        
    if body.get("fromMe") is True:
        return {"status": "skipped", "reason": "Self message"}
        
    print(f'Processing message from {recipient}: "{message_text}"')
    
    # 1. Run the AI Pipeline
    assessment = pipeline.process(message_text)
    
    # 2. Format specifically for WhatsApp
    reply_message = ResponseFormatter.format_whatsapp(assessment)
    
    # Send the reply back to WireWeb
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                'https://app.wireweb.co.in/api/v1/messages',
                json={
                    "sessionId": WIREWEB_SESSION_ID,
                    "to": recipient,
                    "text": reply_message
                },
                headers={
                    "Authorization": f"Bearer {WIREWEB_API_KEY}",
                    "Content-Type": "application/json"
                }
            )
            print(f"Sent report to {recipient}:", response.text)
            return {"status": "success"}
        except Exception as e:
            print("Error sending message:", str(e))
            return {"status": "error", "message": str(e)}