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
