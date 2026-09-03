import os
from supabase import create_client, Client

class Database:
    def __init__(self):
        url: str = os.getenv("SUPABASE_URL", "")
        key: str = os.getenv("SUPABASE_KEY", "")
        if url and key:
            self.client: Client = create_client(url, key)
        else:
            self.client = None
            print("Warning: SUPABASE_URL or SUPABASE_KEY not found in environment.")

    def get_or_create_user(self, user_id: str, phone_number: str = None) -> dict:
        """Ensures the user exists in the database and returns the user object."""
        if not self.client:
            return None

        try:
            # Check if user exists
            response = self.client.table("users").select("*").eq("id", user_id).execute()
            if not response.data:
                # Create user
                new_user = {
                    "id": user_id,
                    "phone_number": phone_number
                }
                res = self.client.table("users").insert(new_user).execute()
                return res.data[0] if res.data else new_user
            
            return response.data[0]
        except Exception as e:
            print(f"Supabase Error (get_or_create_user): {e}")
            return None

    def register_phone_number(self, user_id: str, phone_number: str) -> bool:
        """Updates the user's row with their real phone number to activate them."""
        if not self.client:
            return False
            
        try:
            self.client.table("users").update({"phone_number": phone_number}).eq("id", user_id).execute()
            return True
        except Exception as e:
            print(f"Supabase Error (register_phone_number): {e}")
            return False

    def save_message(self, user_id: str, role: str, content: str):
        """Saves a single message to the conversation history."""
        if not self.client:
            return

        try:
            self.client.table("messages").insert({
                "user_id": user_id,
                "role": role,
                "content": content
            }).execute()
        except Exception as e:
            print(f"Supabase Error (save_message): {e}")

    def get_conversation_history(self, user_id: str, limit: int = 5) -> str:
        """Fetches the last N messages for context."""
        if not self.client:
            return ""

        try:
            # Fetch last N messages, ordered by created_at descending, then reverse them so oldest is first
            response = self.client.table("messages").select("*").eq("user_id", user_id).order("created_at", desc=True).limit(limit).execute()
            
            if not response.data:
                return ""
                
            messages = response.data[::-1] # Reverse list to get chronological order
            
            history_text = "\n[Previous Conversation Context:]\n"
            for msg in messages:
                prefix = "User" if msg["role"] == "user" else "AI"
                history_text += f"{prefix}: {msg['content']}\n"
                
            return history_text + "\n[Current Message:]\n"
        except Exception as e:
            print(f"Supabase Error (get_conversation_history): {e}")
            return ""

    def save_dossier(self, report_data: dict) -> str:
        """Saves a complete dossier report to Supabase and indexes high-risk contact entities."""
        if not self.client or not report_data:
            return ""

        try:
            import secrets
            import re

            dossier_id = f"rep_{secrets.token_hex(6)}"

            # Extract top-level report metadata
            report_body = report_data.get("report") or {}
            metadata = report_body.get("metadata") or {}
            exec_summary = report_body.get("executive_summary") or {}

            target_entity = metadata.get("target_entity") or "Unknown Entity"
            verdict = exec_summary.get("verdict") or "inconclusive"
            confidence_score = exec_summary.get("confidence_score") or 0

            # Insert primary dossier record
            dossier_record = {
                "id": dossier_id,
                "target_entity": target_entity,
                "verdict": verdict,
                "confidence_score": confidence_score,
                "report_json": report_data,
            }
            self.client.table("dossiers").insert(dossier_record).execute()

            # ONLY index contact entities IF verdict is high_risk, likely_scam, or suspicious
            if verdict in ["high_risk", "likely_scam", "suspicious"]:
                extracted = report_data.get("extracted_entities") or {}
                phones = extracted.get("phones") or []
                emails = extracted.get("emails") or []
                urls = extracted.get("urls") or []

                takeaway = (exec_summary.get("one_sentence_takeaway") or {}).get("en") or exec_summary.get("primary_threat_vector") or "Flagged in OSINT analysis"

                indexed_rows = []

                # Index organization name
                if target_entity and target_entity != "Unknown Entity":
                    indexed_rows.append({
                        "dossier_id": dossier_id,
                        "entity_type": "organization",
                        "entity_value": target_entity.strip().lower(),
                        "risk_level": verdict,
                        "evidence_summary": f"Flagged organization ({target_entity}): {takeaway[:150]}"
                    })

                # Index phones (normalize digits)
                for ph in phones:
                    clean_ph = re.sub(r"[^\d+]", "", str(ph))
                    if len(clean_ph) >= 7:
                        indexed_rows.append({
                            "dossier_id": dossier_id,
                            "entity_type": "phone",
                            "entity_value": clean_ph,
                            "risk_level": verdict,
                            "evidence_summary": f"Associated with {target_entity}: {takeaway[:150]}"
                        })

                # Index emails
                for em in emails:
                    clean_em = str(em).strip().lower()
                    if "@" in clean_em:
                        indexed_rows.append({
                            "dossier_id": dossier_id,
                            "entity_type": "email",
                            "entity_value": clean_em,
                            "risk_level": verdict,
                            "evidence_summary": f"Email contact for {target_entity}: {takeaway[:150]}"
                        })

                # Index domains from URLs
                for u in urls:
                    clean_url = str(u).strip().lower()
                    domain_match = re.search(r"https?://([^/]+)", clean_url)
                    if domain_match:
                        domain = domain_match.group(1).replace("www.", "")
                        indexed_rows.append({
                            "dossier_id": dossier_id,
                            "entity_type": "domain",
                            "entity_value": domain,
                            "risk_level": verdict,
                            "evidence_summary": f"Domain used by {target_entity}: {takeaway[:150]}"
                        })

                # Batch insert threat index rows if any exist
                if indexed_rows:
                    try:
                        self.client.table("entity_threat_index").insert(indexed_rows).execute()
                    except Exception as idx_err:
                        print(f"Supabase Threat Indexing Warning: {idx_err}")

            return dossier_id
        except Exception as e:
            print(f"Supabase Error (save_dossier): {e}")
            return ""

    def get_dossier_by_id(self, dossier_id: str) -> dict:
        """Fetches a saved dossier from Supabase by share ID."""
        if not self.client or not dossier_id:
            return None

        try:
            res = self.client.table("dossiers").select("*").eq("id", dossier_id).execute()
            if res.data and len(res.data) > 0:
                return res.data[0].get("report_json")
            return None
        except Exception as e:
            print(f"Supabase Error (get_dossier_by_id): {e}")
            return None

    def search_threat_index(self, phones: list = None, emails: list = None, domains: list = None) -> list:
        """Queries entity_threat_index for previously reported scam contact entities."""
        if not self.client:
            return []

        results = []
        try:
            # Query phones
            if phones:
                for ph in phones:
                    import re
                    clean_ph = re.sub(r"[^\d+]", "", str(ph))
                    if len(clean_ph) >= 7:
                        res = self.client.table("entity_threat_index").select("*").eq("entity_type", "phone").eq("entity_value", clean_ph).limit(3).execute()
                        if res.data:
                            results.extend(res.data)

            # Query emails
            if emails:
                for em in emails:
                    clean_em = str(em).strip().lower()
                    if "@" in clean_em:
                        res = self.client.table("entity_threat_index").select("*").eq("entity_type", "email").eq("entity_value", clean_em).limit(3).execute()
                        if res.data:
                            results.extend(res.data)

            # Query domains
            if domains:
                for dom in domains:
                    clean_dom = str(dom).strip().lower().replace("www.", "")
                    res = self.client.table("entity_threat_index").select("*").eq("entity_type", "domain").eq("entity_value", clean_dom).limit(3).execute()
                    if res.data:
                        results.extend(res.data)

            return results
        except Exception as e:
            print(f"Supabase Error (search_threat_index): {e}")
            return []

