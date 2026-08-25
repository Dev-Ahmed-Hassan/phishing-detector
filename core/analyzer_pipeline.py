from core.llm_provider import LLMProvider, ModularReport
from core.database import Database

class AnalyzerPipeline:
    def __init__(self, llm_provider: LLMProvider, db: Database = None):
        self.llm = llm_provider
        self.db = db

    def process(self, user_id: str, text: str, media_bytes: bytes = None, mime_type: str = None) -> ModularReport:
        clean_text = text.strip() if text else ""
        
        # Prepare context if Database is available
        context_block = ""
        if self.db:
            context_block = self.db.get_conversation_history(user_id)
            
        full_prompt = context_block + clean_text
        
        # Step 1: LLM Analysis 
        report = self.llm.analyze(full_prompt, media_bytes, mime_type)
        
        # Step 2: Database Check (Placeholder)
        
        # Step 3: Web Search (Placeholder)
        
        # Save to history if DB available
        if self.db:
            self.db.save_message(user_id, "user", clean_text)
            self.db.save_message(user_id, "assistant", report.specific_analysis)
            
        return report

    def process_web(self, text: str, media_bytes: bytes = None, mime_type: str = None):
        """
        Stateless, DB-free pipeline for the Web App.
        Uses the deterministic Web LLM provider and returns an expanded WebModularReport.
        """
        clean_text = text.strip() if text else ""
        
        # Step 1: LLM Analysis directly with no DB context
        report = self.llm.analyze_web(clean_text, media_bytes, mime_type)
        
        # We can add web-specific steps here later (e.g. searching the web for `report.detected_urls`)
        
        return report
