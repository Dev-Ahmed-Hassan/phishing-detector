import os
import json
import warnings
import concurrent.futures
from google import genai
from google.genai import types

try:
    from ddgs import DDGS
except ImportError:
    from duckduckgo_search import DDGS

warnings.filterwarnings("ignore", module="duckduckgo_search")

class OSINTSearcher:
    def __init__(self, api_key: Optional[str] = None):
        self.clients = []
        if api_key:
            self.clients.append(genai.Client(api_key=api_key))
        else:
            for key_name in ["GEMINI_API_KEY", "GEMINI_API_KEY_2", "GEMINI_API_KEY_3", "GEMINI_API"]:
                key = os.getenv(key_name)
                if key and genai:
                    self.clients.append(genai.Client(api_key=key))

        self.model = "gemini-3.5-flash-lite"
        self.models_to_try = [
            "gemini-3.5-flash-lite",
            "gemini-3.1-flash-lite",
            "gemini-2.5-flash",
            "gemini-2.0-flash"
        ]

    def extract_claims(self, text: str) -> dict:
        """
        Agent 1: Extracts Direct and Indirect claims from the text.
        """
        if not self.clients:
            return {}
            
        prompt = """
        You are a Fact-Checking OSINT Agent. Your job is to extract claims from the provided text that need to be verified against the internet.
        
        DO NOT extract every sentence. Extract a MAXIMUM of 2 Direct Claims and 2 Indirect Claims.
        
        Direct Claims: Specific factual statements (e.g., "Training will be held in Karachi", "Internship at Ubexis").
        Indirect Claims: Implied claims about reputation or association (e.g., "This is a legitimate organization", "Associated with Amazon").
        
        For each claim, generate a highly intelligent search query to verify it. 
        CRITICAL RULES FOR QUERIES:
        1. DO NOT over-constrain the search! If you are verifying a company's existence, use a broad query like: `Ubexis company linkedin` or `Ubexis official website`.
        2. Use advanced operators (like `site:reddit.com`) ONLY when looking for community scam reports.
        3. Avoid using exact match quotes `""` around entire sentences, as it will break the search engine.
        
        Respond ONLY with a JSON object in this exact format:
        {
          "direct_claims": [
             {"claim": "...", "search_query": "..."}
          ],
          "indirect_claims": [
             {"claim": "...", "search_query": "..."}
          ]
        }
        """
        
        for client in self.clients:
            for model_name in self.models_to_try:
                try:
                    response = client.models.generate_content(
                        model=model_name,
                        contents=[text],
                        config=types.GenerateContentConfig(
                            system_instruction=prompt,
                            temperature=0.0,
                            response_mime_type="application/json"
                        )
                    )
                    raw_content = response.text.strip()
                    if raw_content.startswith("```json"):
                        raw_content = raw_content[7:-3].strip()
                    elif raw_content.startswith("```"):
                        raw_content = raw_content[3:-3].strip()
                    return json.loads(raw_content)
                except Exception as e:
                    print(f"OSINT Extraction Error ({model_name}): {e}")
                    continue
        return {}

    def search_web(self, query: str) -> str:
        """
        Python Tool: Searches DuckDuckGo for the query, and deep crawls the top result.
        """
        from core.url_scanner import URLScanner
        try:
            results = DDGS().text(query, max_results=3)
            if not results:
                return f"No results found for '{query}'"
                
            # Extract top URL for deep crawling
            top_url = None
            for r in results:
                href = r.get('href')
                if href and href.startswith('http'):
                    top_url = href
                    break
            
            deep_crawl_text = ""
            if top_url:
                try:
                    # Deep crawl the first link to bypass SEO snippets
                    scan_res = URLScanner.scan_url(top_url)
                    deep_crawl_text = f"  [DEEP CRAWL INTELLIGENCE]: {scan_res}\n"
                except Exception as e:
                    print(f"Deep crawl failed for {top_url}: {e}")
                    pass
                    
            formatted = f"Results for '{query}':\n"
            for i, r in enumerate(results):
                formatted += f"- URL: {r.get('href', 'No URL')}\n  TITLE: {r.get('title', '')}\n  SNIPPET: {r.get('body', '')}\n"
                if i == 0 and deep_crawl_text:
                    formatted += deep_crawl_text
            return formatted
        except Exception as e:
            print(f"DuckDuckGo Error on '{query}': {e}")
            return f"Search failed for '{query}'"

    def judge_claims(self, original_text: str, claims_dict: dict, search_results: str) -> str:
        """
        Agent 2: Evaluates the claims against the search results.
        """
        if not self.client or not search_results.strip():
            return ""
            
        prompt = """
        You are an OSINT Fact-Checking Judge.
        You will be provided with:
        1. The original suspicious message.
        2. Claims extracted from that message.
        3. Real-time web search results from DuckDuckGo (including URLs).
        
        Your job is to compare the claims against the search results. 
        Write a strict, professional intelligence report evaluating the claims.
        
        CRITICAL RULES:
        1. Search engines sometimes return completely irrelevant fallback results. If a search snippet is COMPLETELY IRRELEVANT, IGNORE IT.
        2. HOWEVER, if you find ANY links remotely related to the company/entity (like their LinkedIn, website, social media, or mentions on other sites), you MUST extract the URL and include it in your citations! Even if the footprint is weak, limited, or doesn't prove anything concrete, you MUST provide the link. The user demands concrete URLs.
        3. If all relevant searches return absolutely no data, state that the entity has no verifiable digital footprint.
        
        Respond ONLY with a JSON object in this exact format:
        {
          "verdict": "Your detailed evaluation report here...",
          "citations": ["https://reddit.com/...", "https://trustpilot.com/..."]
        }
        """
        
        content = f"ORIGINAL MESSAGE:\n{original_text}\n\nCLAIMS:\n{json.dumps(claims_dict)}\n\nWEB SEARCH RESULTS:\n{search_results}"
        
        for client in self.clients:
            for model_name in self.models_to_try:
                try:
                    response = client.models.generate_content(
                        model=model_name,
                        contents=[content],
                        config=types.GenerateContentConfig(
                            system_instruction=prompt,
                            temperature=0.2,
                            response_mime_type="application/json"
                        )
                    )
                    raw_content = response.text.strip()
                    if raw_content.startswith("```json"):
                        raw_content = raw_content[7:-3].strip()
                    elif raw_content.startswith("```"):
                        raw_content = raw_content[3:-3].strip()
                    return json.loads(raw_content)
                except Exception as e:
                    print(f"OSINT Judgment Error ({model_name}): {e}")
                    continue
        return ""

    def generate_osint_report(self, text: str) -> str:
        """
        Main orchestration function with a strict timeout.
        """
        # Guardrail: Too short to have claims
        if len(text.split()) < 10:
            return ""
            
        try:
            # 1. Extract
            claims = self.extract_claims(text)
            
            # Gather all queries
            queries = []
            if "direct_claims" in claims:
                for c in claims["direct_claims"]:
                    if "search_query" in c:
                        queries.append(c["search_query"])
            if "indirect_claims" in claims:
                for c in claims["indirect_claims"]:
                    if "search_query" in c:
                        queries.append(c["search_query"])
                        
            if not queries:
                return ""
                
            # 2. Search concurrently
            search_results = ""
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                # We limit to max 4 queries to be safe
                results = executor.map(self.search_web, queries[:4])
                for r in results:
                    search_results += r + "\n"
                    
            # 3. Judge
            judge_json = self.judge_claims(text, claims, search_results)
            
            if judge_json and "verdict" in judge_json:
                verdict = judge_json.get("verdict", "")
                citations = judge_json.get("citations", [])
                
                final_str = f"\n[SYSTEM WEB SEARCH INTELLIGENCE]\n{verdict}\n"
                if citations:
                    final_str += "CITATIONS:\n" + "\n".join([f"- {c}" for c in citations]) + "\n"
                final_str += "[END WEB SEARCH INTELLIGENCE]\n"
                return final_str
                
            return ""
            
        except Exception as e:
            print(f"OSINT Pipeline Error: {e}")
            return ""
            
    @classmethod
    def run_with_timeout(cls, text: str, timeout: int = 15) -> str:
        """
        Runs the OSINT pipeline with a strict timeout to ensure graceful degradation.
        """
        searcher = cls()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(searcher.generate_osint_report, text)
            try:
                # Block for a maximum of 15 seconds
                return future.result(timeout=timeout)
            except concurrent.futures.TimeoutError:
                print("🚨 OSINT Pipeline Timed Out! Gracefully degrading...")
                return ""
            except Exception as e:
                print(f"🚨 OSINT Pipeline Crashed: {e}")
                return ""
