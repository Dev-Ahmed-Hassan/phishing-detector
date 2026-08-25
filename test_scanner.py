from core.url_scanner import URLScanner

def test():
    print("=== URL SCANNER TEST ===")
    
    # Let's test a polite message that has a suspicious link hidden in it
    test_message = """
    Hello! I found this amazing data entry job at Amazon Pakistan! 
    You can earn 50,000 Rs a day. Just click here to register:
    https://clone-portfolio-site.vercel.app/
    
    (I also checked out google.com and it looks cool).
    """
    
    print(f"Testing on message:\n{test_message}")
    print("\n--- RUNNING SCANNER ---")
    
    # This will extract the links, ignore google.com, and scan the fake one!
    report = URLScanner.generate_system_report(test_message)
    
    print(report)
    print("\n=== TEST COMPLETE ===")

if __name__ == "__main__":
    test()
