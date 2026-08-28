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
        from core.url_scanner import URLScanner
        from core.osint_searcher import OSINTSearcher
        
        clean_text = text.strip() if text else ""
        
        # --- AGENTIC URL SANDBOXING ---
        system_report = URLScanner.generate_system_report(clean_text)
        
        if system_report:
            print(f"🕵️  [PIPELINE] URL Scanner triggered. Injecting intelligence...")
            clean_text += f"\n\n{system_report}"
            
        # --- OSINT FACT-CHECKING ---
        print(f"🌐 [PIPELINE] Running OSINT Web Searcher...")
        osint_report = OSINTSearcher.run_with_timeout(clean_text, timeout=15)
        
        if osint_report:
            print(f"🌐 [PIPELINE] OSINT Intelligence retrieved. Injecting...")
            clean_text += f"\n\n{osint_report}"
        
        # Step 1: LLM Analysis directly with no DB context
        report = self.llm.analyze_web(clean_text, media_bytes, mime_type)
        
        # Ensure detected URLs from the scanner are included in the final report
        # if the LLM missed them or couldn't extract them.
        scraped_urls = URLScanner.extract_urls(text)
        if scraped_urls:
            report.detected_urls = list(set(report.detected_urls + scraped_urls))
        
        return report
