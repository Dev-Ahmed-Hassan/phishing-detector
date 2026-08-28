from core.osint_searcher import OSINTSearcher
import os

def test():
    # Make sure we have an API key loaded for testing
    if not os.getenv("GEMINI_API_KEY") and not os.getenv("GEMINI_API_KEY_2") and not os.getenv("GEMINI_API_KEY_3"):
        print("WARNING: No GEMINI_API_KEY found in environment variables. Extraction/Judgment will fail.")
        
    print("=== OSINT SEARCHER TEST ===")
    
    test_message = """
    Ubexis is offering a two-month remote internship opportunity designed to help you learn, grow, and build your future. By joining this program, you will get to work on real projects while learning directly from industry experts. They are currently looking to fill internship roles in three areas: **Web Development**, where you will build responsive websites and applications using modern technologies; **Business Development**, which involves researching and creating opportunities to drive business growth; and **Digital Content Creation**, where you will create engaging content that informs, inspires, and connects. If you are ready to get started and want access to this great learning experience, you can send your resume to hr@ubexis.com. Make sure to apply before the deadline on July 10, 2026.
    """
    
    print(f"Testing on message:\n{test_message}")
    
    print("\n--- STEP 1: CLAIM EXTRACTION ---")
    searcher = OSINTSearcher()
    claims = searcher.extract_claims(test_message)
    print("Extracted JSON from AI:")
    import json
    print(json.dumps(claims, indent=2))
    
    print("\n--- STEP 2: DUCKDUCKGO WEB SEARCH ---")
    queries = []
    if "direct_claims" in claims:
        for c in claims["direct_claims"]:
            if "search_query" in c: queries.append(c["search_query"])
    if "indirect_claims" in claims:
        for c in claims["indirect_claims"]:
            if "search_query" in c: queries.append(c["search_query"])
            
    search_results = ""
    for q in queries:
        print(f"\nSearching for: '{q}'...")
        res = searcher.search_web(q)
        print(res)
        search_results += res + "\n"
        
    print("\n--- STEP 3: JUDGMENT AGENT ---")
    verdict = searcher.judge_claims(test_message, claims, search_results)
    
    print("\n--- FINAL OSINT REPORT ---")
    if verdict:
        print(verdict)
    else:
        print("Pipeline aborted or failed.")
        
    print("\n=== TEST COMPLETE ===")

if __name__ == "__main__":
    test()
