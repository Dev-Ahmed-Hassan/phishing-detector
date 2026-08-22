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
    def format_json(report: ModularReport) -> dict:
        """Formats the assessment as a raw dictionary for the Web App"""
        return report.dict()
