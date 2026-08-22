from core.llm_provider import LLMProvider, ModularReport

class AnalyzerPipeline:
    def __init__(self, llm_provider: LLMProvider):
        self.llm = llm_provider

    def process(self, text: str) -> ModularReport:
        clean_text = text.strip()
        
        # Step 1: LLM Analysis (Detect language, extract specifics)
        report = self.llm.analyze(clean_text)
        
        # Step 2: Database Check (Placeholder for Lego Block)
        # TODO: Lookup phone numbers or company names in Supabase
        # if found: report.database_findings = "This number was reported 3 times."
        
        # Step 3: Web Search (Placeholder for Lego Block)
        # TODO: Run Google Custom Search on company name
        # if found: report.web_search_findings = "Company website registered 2 days ago."
        
        return report
