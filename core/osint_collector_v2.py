import os
import re
import json
import time
import whois
import httpx
import requests
import datetime
import threading
import warnings
import urllib.parse
import concurrent.futures
from typing import List, Dict, Any, Optional, Tuple
from bs4 import BeautifulSoup

try:
    from ddgs import DDGS
except ImportError:
    from duckduckgo_search import DDGS

warnings.filterwarnings("ignore")

class OSINTCollectorV2:
    """
    Standalone V2 OSINT Evidence Collector.
    Executes empirical, intent-categorized tools in parallel:
    1. Category 1: URL Safety & Verification (WHOIS, TLD check, HTTP status, redirect check, BeautifulSoup scraping)
    2. Category 2: Official Corporate Presence (LinkedIn profile, Official website, WHOIS of discovered candidates)
    3. Category 3: Community Scam & Reputation (Open Web scam, Reviews, Reddit keyword)
    4. Category 4: Claim Verification (Targeted English queries)
    5. Category 5: Phone Number Reputation (Local, International & Global 10-digit number support)

    Plus domain intelligence: WHOIS lookup on email domains.

    Query design: organization name is always quoted (`"CodeAlpha" scam`) to force exact-match
    relevance. Exactly one targeted `site:` search exists in the whole pipeline (LinkedIn,
    Category 2); all reputation queries are general so DuckDuckGo decides where relevance
    lives instead of starving on weakly-indexed platforms.

    Every search records `search_status` ("ok" | "no_results" | "failed") so the Phase 3
    Judge can distinguish "no evidence exists" from "search infrastructure failed".

    Includes 3-Stage Search Failover (ddgs auto-rotating backends -> pinned Yahoo
    engine -> DuckDuckGo HTML POST Fallback) and 3-Layer Deep Page Scraper
    (httpx -> requests -> Jina AI Reader -> Null Fallback).
    Strictly performs empirical evidence gathering only. Zero risk scoring or decision-making.
    """

    TRUSTED_GOV_TLDS = ['.gov.pk', '.edu.pk', '.gob.pk', '.gov', '.edu', '.ac.uk', '.gov.uk']

    def __init__(self):
        pass

    def collect_evidence(self, extraction_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point for Step 2 Evidence Collection.
        Receives the Step 1 consolidated JSON output.
        """
        master_data = extraction_data.get("consolidated_master_result", extraction_data)
        
        org_name = master_data.get("organization_name")
        urls = master_data.get("all_unique_urls", [])
        emails = master_data.get("all_unique_emails", [])
        claims = master_data.get("unique_verifiable_claims", [])
        phones = master_data.get("all_unique_phones", [])

        # Parallel Execution of Evidence Gathering Passes
        url_verifications = []
        official_presence_searches = []
        official_site_candidates = []
        community_scam_searches = []
        claim_verifications = []
        phone_number_searches = []
        email_domain_intelligence = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            # Task 1: URL Verification
            future_urls = executor.submit(self._verify_urls, urls)

            # Task 2: Official Presence Searches (Skipped if org_name is null)
            future_presence = executor.submit(self._search_official_presence, org_name) if org_name else None

            # Task 3: Community Scam Searches (Skipped if org_name is null)
            future_reputation = executor.submit(self._search_community_reputation, org_name) if org_name else None

            # Task 4: Claim Verifications
            future_claims = executor.submit(self._verify_claims, claims, org_name) if claims else None

            # Task 5: Phone Number Searches
            future_phones = executor.submit(self._search_phone_numbers, phones) if phones else None

            # Task 6: Email Domain WHOIS
            future_email_domains = executor.submit(self._analyze_email_domains, emails) if emails else None

            # Wait for results
            url_verifications = future_urls.result() if future_urls else []
            presence_data = future_presence.result() if future_presence else {}
            community_scam_searches = future_reputation.result() if future_reputation else []
            claim_verifications = future_claims.result() if future_claims else []
            phone_number_searches = future_phones.result() if future_phones else []
            email_domain_intelligence = future_email_domains.result() if future_email_domains else []

            official_presence_searches = presence_data.get("official_presence_searches", [])
            official_site_candidates = presence_data.get("official_site_candidates", [])

        # Non-blocking Community Threat Database Lookup
        community_db_matches = []
        try:
            from core.database import Database
            db_inst = Database()
            community_db_matches = db_inst.search_threat_index(org_name=org_name, phones=phones, emails=emails, domains=urls)
        except Exception as db_err:
            print(f"OSINT Collector Threat DB Lookup Notice: {db_err}")

        return {
          "target_entity_name": org_name,
          "url_verifications": url_verifications,
          "official_presence_searches": official_presence_searches,
          "official_site_candidates": official_site_candidates,
          "community_scam_searches": community_scam_searches,
          "claim_verifications": claim_verifications,
          "phone_number_searches": phone_number_searches,
          "email_domain_intelligence": email_domain_intelligence,
          "community_db_matches": community_db_matches
        }

    # ==========================================================================
    # Category 1: URL Safety & Verification
    # ==========================================================================
    def _verify_urls(self, urls: List[str]) -> List[Dict[str, Any]]:
        results = []
        for url in urls[:3]: # Limit to top 3 URLs to avoid rate limits
            results.append(self._inspect_single_url(url))
        return results

    def _inspect_single_url(self, url: str) -> Dict[str, Any]:
        domain = url.replace('https://', '').replace('http://', '').split('/')[0].lower()
        is_gov_tld = any(domain.endswith(tld) for tld in self.TRUSTED_GOV_TLDS)
        
        info = {
            "intent": "Verify domain legitimacy, WHOIS age, HTTP status, redirects, and deep page content",
            "target_url": url,
            "domain": domain,
            "is_government_tld": is_gov_tld,
            "whois_creation_date": None,
            "http_status": None,
            "redirect_warning": False,
            "page_title": None,
            "scraped_content_snippet": None
        }

        # 1. WHOIS Lookup
        try:
            domain_info = whois.whois(domain)
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date:
                info["whois_creation_date"] = creation_date.strftime('%Y-%m-%d')
        except Exception:
            info["whois_creation_date"] = None

        # 2. Deep Scrape Page Content (Direct + Requests + Jina AI Reader Fallback)
        deep_text = self._deep_scrape_url(url)
        if deep_text:
            info["scraped_content_snippet"] = deep_text

        # 3. HTTP Status & Redirect Check
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'}
            with httpx.Client(timeout=6.0, follow_redirects=True) as client:
                response = client.get(url, headers=headers)
                info["http_status"] = response.status_code
                
                if response.status_code == 200 and not info["page_title"]:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    title = soup.title.string if soup.title else None
                    if title:
                        info["page_title"] = title.strip().replace('\n', ' ')
                    
                    meta_refresh = soup.find('meta', attrs={'http-equiv': re.compile(r'refresh', re.I)})
                    js_redirect = any('window.location' in s.string or 'location.replace' in s.string for s in soup.find_all('script') if s.string)
                    if meta_refresh or js_redirect:
                        info["redirect_warning"] = True
        except Exception:
            pass

        return info

    # ==========================================================================
    # Category 2: Official Corporate Presence Searches
    # ==========================================================================
    def _search_official_presence(self, org_name: str) -> Dict[str, Any]:
        searches = []

        # Sub-Task A: LinkedIn Profile Search
        q_linkedin = f'"{org_name}" site:linkedin.com/company'
        results, status = self._execute_ddg_search(q_linkedin)
        searches.append({
            "search_type": "LinkedIn Corporate Profile Search",
            "intent": f"Find official corporate LinkedIn profile for '{org_name}'",
            "target_entity": org_name,
            "query_used": q_linkedin,
            "search_status": status,
            "results": results
        })

        # Sub-Task B: Official Website Search
        q_website = f'"{org_name}" official website'
        results, status = self._execute_ddg_search(q_website)
        searches.append({
            "search_type": "Official Website Search",
            "intent": f"Find official company website for '{org_name}'",
            "target_entity": org_name,
            "query_used": q_website,
            "search_status": status,
            "results": results
        })

        # WHOIS the candidate official-site domains discovered above
        candidate_domains = self._extract_candidate_domains(results, max_candidates=3)
        whois_candidates = []
        if candidate_domains:
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as whois_executor:
                future_whois = {whois_executor.submit(self._whois_creation_date, domain): (domain, url)
                                for domain, url in candidate_domains}
                for future in concurrent.futures.as_completed(future_whois):
                    domain, source_url = future_whois[future]
                    creation_date, whois_status = future.result()
                    whois_candidates.append({
                        "domain": domain,
                        "source_search_type": "Official Website Search",
                        "source_url": source_url,
                        "whois_creation_date": creation_date,
                        "whois_lookup_status": whois_status
                    })

        return {
            "official_presence_searches": searches,
            "official_site_candidates": whois_candidates
        }

    # ==========================================================================
    # Category 3: Community Scam & Reputation Searches
    # ==========================================================================
    def _search_community_reputation(self, org_name: str) -> List[Dict[str, Any]]:
        searches = []

        # Sub-Task A: General Open Web Scam Search
        q_scam = f'"{org_name}" scam'
        results, status = self._execute_ddg_search(q_scam)
        searches.append({
            "search_type": "General Open Web Scam Search",
            "intent": f"Find scam reports, fraud complaints, or warnings for '{org_name}' across the open web",
            "target_entity": org_name,
            "query_used": q_scam,
            "search_status": status,
            "results": results
        })

        # Sub-Task B: General Reviews Search
        q_reviews = f'"{org_name}" reviews'
        results, status = self._execute_ddg_search(q_reviews)
        searches.append({
            "search_type": "General Reputation & Reviews Search",
            "intent": f"Find employee, candidate, and customer reviews for '{org_name}' across any review platform",
            "target_entity": org_name,
            "query_used": q_reviews,
            "search_status": status,
            "results": results
        })

        # Sub-Task C: Reddit Search
        q_reddit = f'"{org_name}" reddit'
        results, status = self._execute_ddg_search(q_reddit)
        searches.append({
            "search_type": "Reddit Community Search",
            "intent": f"Find Reddit community discussions, complaints, or warnings about '{org_name}'",
            "target_entity": org_name,
            "query_used": q_reddit,
            "search_status": status,
            "results": results
        })

        return searches

    # ==========================================================================
    # Category 4: Claim Verification Searches
    # ==========================================================================
    def _verify_claims(self, claims: List[Dict[str, Any]], org_name: Optional[str]) -> List[Dict[str, Any]]:
        verifications = []
        for claim_item in claims[:3]:
            claim_text = claim_item.get("claim", "")
            query = claim_item.get("search_query", "")
            
            if query:
                results, status = self._execute_ddg_search(query)
                verifications.append({
                    "search_type": "Claim Fact-Check Search",
                    "intent": f"Verify specific claim: '{claim_text}'",
                    "target_entity": org_name or "Unknown",
                    "claim_checked": claim_text,
                    "query_used": query,
                    "search_status": status,
                    "results": results
                })
        return verifications

    # ==========================================================================
    # Category 5: Phone Number Reputation Searches
    # ==========================================================================
    def _search_phone_numbers(self, phones: List[str]) -> List[Dict[str, Any]]:
        """
        Search open-web mentions for each unique phone number.
        Supports Pakistani (+92/03...), US (10-digit), and International number formats.
        """
        results = []
        for phone in phones[:2]:  # Cap at 2 numbers to control query budget
            queries = []

            # Normalize: strip spaces/dashes/parentheses
            digits_only = re.sub(r'\D', '', phone)

            # Build query formats
            if digits_only.startswith("92") and len(digits_only) == 12:
                intl = "+" + digits_only
                local = "0" + digits_only[2:]
                queries = [f'"{intl}"', f'"{local}"']
            elif digits_only.startswith("3") and len(digits_only) == 10:
                intl = "+92" + digits_only
                local = "0" + digits_only
                queries = [f'"{intl}"', f'"{local}"']
            elif digits_only.startswith("03") and len(digits_only) == 11:
                intl = "+92" + digits_only[1:]
                local = digits_only
                queries = [f'"{intl}"', f'"{local}"']
            elif len(digits_only) == 10:
                # 10-Digit Global / US Number (e.g. 9088290335)
                queries = [f'"{digits_only}"', f'"+1{digits_only}"', f'"{phone}"']
            else:
                queries = [f'"{phone}"', f'"{digits_only}"']

            all_results = []
            statuses = []
            for q in set(queries): # Unique queries
                res, status = self._execute_ddg_search(q)
                all_results.extend(res)
                statuses.append(status)

            # Deduplicate by URL
            seen_urls = set()
            deduped = []
            for r in all_results:
                url = r.get("url", "")
                if url and url in seen_urls:
                    continue
                seen_urls.add(url)
                deduped.append(r)

            overall_status = "ok" if any(s == "ok" for s in statuses) else (
                "no_results" if all(s == "no_results" for s in statuses) else "failed"
            )

            results.append({
                "target_phone_number": phone,
                "intent": "Find open-web mentions, call-reputation listings, and complaints for phone number",
                "queries_used": list(set(queries)),
                "search_status": overall_status,
                "results": deduped
            })

        return results

    # ==========================================================================
    # Domain Intelligence Helpers
    # ==========================================================================
    def _analyze_email_domains(self, emails: List[str]) -> List[Dict[str, Any]]:
        """
        Run WHOIS on unique email domains (e.g. hr@ubexis.com -> ubexis.com).
        Returns creation date facts; leaves interpretation to the Judge.
        """
        results = []
        seen_domains = set()

        for email in emails[:3]:  # Cap at 3 email addresses
            if "@" not in email:
                continue
            domain = email.split("@")[-1].strip().lower()
            if not domain or domain in seen_domains:
                continue
            seen_domains.add(domain)

            creation_date, whois_status = self._whois_creation_date(domain)
            results.append({
                "email_domain": domain,
                "sample_email": email,
                "whois_creation_date": creation_date,
                "whois_lookup_status": whois_status
            })

        return results

    def _extract_candidate_domains(self, search_results: List[Dict[str, Any]], max_candidates: int = 3) -> List[Tuple[str, str]]:
        """
        Extract unique candidate domains from search result URLs.
        Returns list of (domain, source_url) tuples.
        """
        candidates = []
        seen_domains = set()

        for r in search_results:
            url = r.get("url", "")
            if not url or not url.startswith("http"):
                continue
            try:
                domain = urllib.parse.urlparse(url).netloc.lower().replace("www.", "")
            except Exception:
                continue
            if not domain or domain in seen_domains:
                continue
            seen_domains.add(domain)
            candidates.append((domain, url))
            if len(candidates) >= max_candidates:
                break

        return candidates

    def _whois_creation_date(self, domain: str) -> Tuple[Optional[str], str]:
        """
        Empirical WHOIS lookup. Returns (creation_date_string, status).
        Status: "ok", "no_date", or "failed".
        """
        try:
            domain_info = whois.whois(domain)
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if isinstance(creation_date, datetime.datetime):
                return creation_date.strftime('%Y-%m-%d'), "ok"
            if isinstance(creation_date, str):
                # Keep just the date portion if it contains time
                return creation_date.split('T')[0], "ok"
            return None, "no_date"
        except Exception as e:
            print(f"WHOIS lookup failed for {domain}: {e}")
            return None, "failed"

    # ==========================================================================
    # Helper: Search Execution with Automatic 3-Stage Failover
    # ==========================================================================
    _ddg_gate = threading.Lock()
    _last_ddg_query_ts = 0.0
    DDG_MIN_INTERVAL = 1.0

    def _throttle_ddg(self):
        with self._ddg_gate:
            now = time.monotonic()
            wait = self.DDG_MIN_INTERVAL - (now - self._last_ddg_query_ts)
            if wait > 0:
                time.sleep(wait)
            self._last_ddg_query_ts = time.monotonic()

    def _execute_ddg_search(self, query: str, max_results: int = 5) -> Tuple[List[Dict[str, Any]], str]:
        # Plan A: ddgs auto-rotating backends
        raw_results = self._try_ddgs_backend(query, max_results, backend="auto")

        # Plan B: pinned Yahoo engine
        if raw_results is None:
            raw_results = self._try_ddgs_backend(query, max_results, backend="yahoo")

        # Plan C: Direct DDG HTML Endpoint
        if raw_results is None:
            for attempt in range(2):
                self._throttle_ddg()
                raw_results = self._ddg_html_failover(query, max_results=max_results)
                if raw_results is not None:
                    break
                time.sleep(2.0)

        if raw_results is None:
            return [], "failed"
        return self._format_search_results(raw_results), ("ok" if raw_results else "no_results")

    def _try_ddgs_backend(self, query: str, max_results: int, backend: str) -> Optional[List[Dict[str, Any]]]:
        for attempt in range(2):
            self._throttle_ddg()
            try:
                return list(DDGS().text(query, max_results=max_results, backend=backend))
            except Exception as e:
                if "No results found" in str(e):
                    return []
                time.sleep(1.5)
        return None

    def _format_search_results(self, raw_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        formatted = []
        if raw_results:
            for idx, r in enumerate(raw_results):
                url = r.get('href', '') or r.get('url', '')
                title = r.get('title', '')
                snippet = r.get('body', '') or r.get('snippet', '')

                # Deep crawl top result URL for deep webpage content
                full_page_content = None
                if idx == 0 and url and url.startswith('http'):
                    full_page_content = self._deep_scrape_url(url)

                formatted.append({
                    "title": title,
                    "url": url,
                    "search_snippet": snippet,
                    "full_page_content": full_page_content
                })
        return formatted

    # Direct DuckDuckGo HTML Failover
    def _ddg_html_failover(self, query: str, max_results: int = 5) -> Optional[List[Dict[str, str]]]:
        url = "https://html.duckduckgo.com/html/"
        data = {"q": query}
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'}
        results = []
        try:
            with httpx.Client(timeout=8.0, follow_redirects=True) as client:
                resp = client.post(url, data=data, headers=headers)
                if resp.status_code != 200:
                    return None
                soup = BeautifulSoup(resp.text, 'html.parser')
                for a in soup.find_all('a', class_='result__a', limit=max_results):
                    title = a.get_text(strip=True)
                    raw_href = a.get('href', '')

                    clean_url = raw_href
                    if '/l/?uddg=' in raw_href:
                        parsed = urllib.parse.parse_qs(urllib.parse.urlparse(raw_href).query)
                        if 'uddg' in parsed:
                            clean_url = parsed['uddg'][0]

                    snippet = ""
                    parent = a.find_parent('div', class_='result')
                    if parent:
                        snip_elem = parent.find('a', class_='result__snippet')
                        if snip_elem:
                            snippet = snip_elem.get_text(strip=True)

                    results.append({
                        "title": title,
                        "href": clean_url,
                        "body": snippet
                    })
                return results
        except Exception:
            return None

    # ==========================================================================
    # Helper: 3-Layer Anti-Blocking Deep Webpage Scraper
    # ==========================================================================
    def _deep_scrape_url(self, url: str) -> Optional[str]:
        if not url or not url.startswith('http'):
            return None

        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'}

        # Layer 1: Direct httpx Request
        try:
            with httpx.Client(timeout=5.0, follow_redirects=True) as client:
                response = client.get(url, headers=headers)
                if response.status_code == 200 and response.text:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    for tag in soup(["script", "style", "noscript", "header", "footer", "nav"]):
                        tag.decompose()
                    text = soup.get_text(separator=' ', strip=True)
                    words = text.split()
                    if len(words) > 30:
                        return ' '.join(words[:600])
        except Exception:
            pass

        # Layer 2: Standard requests library Fallback
        try:
            resp = requests.get(url, headers=headers, timeout=5.0)
            if resp.status_code == 200 and resp.text:
                soup = BeautifulSoup(resp.text, 'html.parser')
                for tag in soup(["script", "style", "noscript", "header", "footer", "nav"]):
                    tag.decompose()
                text = soup.get_text(separator=' ', strip=True)
                words = text.split()
                if len(words) > 30:
                    return ' '.join(words[:600])
        except Exception:
            pass

        # Layer 3: Jina AI Reader Fallback
        try:
            jina_url = f"https://r.jina.ai/{url}"
            with httpx.Client(timeout=7.0, follow_redirects=True) as client:
                jina_response = client.get(jina_url, headers=headers)
                if jina_response.status_code == 200 and jina_response.text:
                    jina_text = jina_response.text.strip()
                    words = jina_text.split()
                    if len(words) > 30:
                        return ' '.join(words[:600])
        except Exception:
            pass

        return None
