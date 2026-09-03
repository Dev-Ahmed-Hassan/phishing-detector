from core.llm_provider import ModularReport

class ResponseFormatter:
    @staticmethod
    def format_whatsapp(report: ModularReport) -> str:
        """Formats the ModularReport for WhatsApp, assembling it like Lego blocks."""
        
        # --- HEADER BLOCK ---
        if report.risk_level.lower() == "high":
            header = "*WARNING: HIGH RISK SCAM*"
        elif report.risk_level.lower() == "medium":
            header = "*CAUTION: SUSPICIOUS*"
        else:
            header = "*LOW RISK*"
            
        message = f"{header}\n\n"
        
        # --- BLOCK 1: Specific Analysis (Always Present) ---
        message += f"{report.specific_analysis}\n\n"
        
        # --- BLOCK 2: Database Findings (Optional Lego Block) ---
        if report.database_findings:
            message += f"*Database Check:* {report.database_findings}\n\n"
            
        # --- BLOCK 3: Web Search Findings (Optional Lego Block) ---
        if report.web_search_findings:
            message += f"*Web Search:* {report.web_search_findings}\n\n"
            
        # --- BLOCK 4: Recommended Action (Always Present) ---
        message += f"*Next Steps:* {report.recommended_action}"
        
        return message

    @staticmethod
    def format_whatsapp_v2(payload: dict, dossier_id: str = "") -> str:
        """Formats the V2 report payload for WhatsApp."""
        report = payload.get("report") or {}
        exec_summary = report.get("executive_summary") or {}
        user_report = report.get("user_facing_report") or {}
        takeaway = exec_summary.get("one_sentence_takeaway") or {}
        
        verdict = (exec_summary.get("verdict") or "inconclusive").lower()
        score = exec_summary.get("confidence_score", 0)
        target = report.get("metadata", {}).get("target_entity") or payload.get("extracted_entities", {}).get("organization_name") or "Target Entity"

        if verdict in ["high_risk", "likely_scam"]:
            header = "🔴 *WARNING: LIKELY SCAM*"
        elif verdict in ["suspicious", "medium_risk"]:
            header = "🟡 *CAUTION: SUSPICIOUS OFFER*"
        else:
            header = "🟢 *LOW RISK: VERIFIED PRESENCE*"

        msg = f"{header}\n"
        msg += f"*Target Entity:* {target}\n"
        msg += f"*Authenticity Score:* {score}/100\n\n"

        takeaway_text = takeaway.get("en") or takeaway.get("user_language") or ""
        if takeaway_text:
            msg += f"*Summary:* {takeaway_text}\n\n"

        actions = user_report.get("what_you_should_do") or []
        if actions:
            msg += "*What You Should Do:*\n"
            for act in actions[:3]:
                msg += f"• {act}\n"
            msg += "\n"

        if dossier_id:
            msg += f"📄 *View Full Report & Download PDF:*\n"
            msg += f"https://naukrinigran.vercel.app/report/{dossier_id}\n"

        return msg.strip()

    @staticmethod
    def format_json(report: ModularReport) -> dict:
        """Formats the assessment as a raw dictionary for the Web App"""
        return report.dict()
