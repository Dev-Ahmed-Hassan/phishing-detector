import re
import httpx
import whois
from bs4 import BeautifulSoup
from typing import List

class URLScanner:
    URL_REGEX = re.compile(r'(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?)')

    @classmethod
    def extract_urls(cls, text: str) -> List[str]:
        """Extract all potential URLs from a text block."""
        urls = cls.URL_REGEX.findall(text)
        # Clean up trailing punctuation that regex might catch
        cleaned_urls = []
        for url in urls:
            url = url.rstrip('.,!?"\'')
            if not url.startswith('http'):
                url = 'http://' + url
            cleaned_urls.append(url)
        return list(set(cleaned_urls))

    @classmethod
    def scan_url(cls, url: str) -> str:
        """
        Scans a single URL.
        1. Performs WHOIS to get domain age.
        2. Fetches the HTML to get the <title>.
        Returns a formatted intelligence string.
        """
        domain = url.replace('https://', '').replace('http://', '').split('/')[0]
        
        intelligence = []
        intelligence.append(f"TARGET URL: {url}")
        
        # 1. WHOIS Lookup
        try:
            domain_info = whois.whois(domain)
            creation_date = domain_info.creation_date
            
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
                
            if creation_date:
                intelligence.append(f"DOMAIN REGISTERED: {creation_date.strftime('%Y-%m-%d')}")
            else:
                intelligence.append(f"DOMAIN REGISTERED: Unknown (Suspicious)")
        except Exception:
            intelligence.append(f"DOMAIN REGISTERED: WHOIS Lookup Failed (Highly Suspicious/Hidden)")

        # 2. HTML Scraping
        try:
            with httpx.Client(timeout=5.0, follow_redirects=True) as client:
                # Use a standard user agent to avoid basic bot blocks
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
                response = client.get(url, headers=headers)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # 1. Get Title
                    title = soup.title.string if soup.title else "No Title"
                    title = title.strip().replace('\n', ' ')
                    intelligence.append(f"WEBPAGE TITLE: '{title}'")
                    
                    # 2. Check for Hidden JS/Meta Redirects (Classic Phishing trick)
                    meta_refresh = soup.find('meta', attrs={'http-equiv': re.compile(r'refresh', re.I)})
                    js_redirect_target = None
                    for script in soup.find_all('script'):
                        if script.string and ('window.location' in script.string or 'location.replace' in script.string or 'location.href' in script.string):
                            # Extremely simple check for the presence of JS redirect
                            js_redirect_target = True
                            
                    if meta_refresh or js_redirect_target:
                        intelligence.append("WARNING: HIDDEN REDIRECT DETECTED (Scam sites often use JS/Meta redirects to hide their true destination)")

                    # 3. Deep Content Scraping (Get Body Text)
                    # Remove scripts and styles
                    for script in soup(["script", "style", "noscript"]):
                        script.decompose()
                    
                    body_text = soup.get_text(separator=' ', strip=True)
                    # Limit to ~500 words to avoid massive prompts
                    words = body_text.split()
                    if len(words) > 500:
                        body_text = ' '.join(words[:500]) + "... [TRUNCATED]"
                    else:
                        body_text = ' '.join(words)
                        
                    if body_text:
                        intelligence.append(f"WEBPAGE CONTENT SNIPPET: {body_text}")
                    else:
                        intelligence.append(f"WEBPAGE CONTENT SNIPPET: (No readable text found)")
                        
                else:
                    intelligence.append(f"WEBPAGE STATUS: Returns HTTP {response.status_code}")
        except httpx.RequestError:
            intelligence.append("WEBPAGE STATUS: Unreachable (Server down or blocking scrapers)")
        except Exception as e:
            intelligence.append(f"WEBPAGE STATUS: Error accessing page ({str(e)})")

        return " | ".join(intelligence)

    TRUSTED_DOMAINS = [
        'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'x.com', 
        'instagram.com', 'linkedin.com', 'tiktok.com', 'amazon.com', 'apple.com'
    ]

    @classmethod
    def generate_system_report(cls, text: str) -> str:
        """
        Extracts URLs and generates a combined system context block.
        Returns an empty string if no URLs are found.
        """
        urls = cls.extract_urls(text)
        if not urls:
            return ""
            
        # Filter out extremely common trusted domains so scammers can't use them as "padding"
        suspicious_urls = []
        for url in urls:
            domain = url.replace('https://', '').replace('http://', '').split('/')[0].lower()
            # If the domain doesn't end with a trusted domain (e.g. ignoring www.google.com)
            if not any(domain.endswith(trusted) for trusted in cls.TRUSTED_DOMAINS):
                suspicious_urls.append(url)
            
        if not suspicious_urls:
            return ""
            
        reports = []
        for url in suspicious_urls[:3]: # Limit to 3 to prevent abuse/timeouts
            reports.append(cls.scan_url(url))
            
        final_report = "\n[SYSTEM AUTOMATED URL SCAN]\n"
        final_report += "\n".join([f"- {r}" for r in reports])
        final_report += "\n[END AUTOMATED SCAN]"
        
        return final_report
