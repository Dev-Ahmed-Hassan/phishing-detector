-- Migration: 001_initial_schema
-- Description: Creates the core tables for user tracking and context preservation (session history)

-- Create the Users table
-- We use the WhatsApp/WireWeb 'sender' or 'chat' ID as the primary key here, not a UUID.
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    phone_number TEXT, -- Nullable, we only save it if WhatsApp exposes it
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- Create the Messages table for Context Preservation
-- This acts as the memory for the AI.
CREATE TABLE messages (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
    content TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- Index for faster context retrieval (since we order by created_at)
CREATE INDEX idx_messages_user_id ON messages(user_id);
CREATE INDEX idx_messages_created_at ON messages(created_at);
