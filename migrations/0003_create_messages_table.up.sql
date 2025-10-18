CREATE TABLE messages (
    id SERIAL PRIMARY KEY,
    instance_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    conversation_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    sender_jid TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    text_content TEXT,
    audio_content BYTEA,
    message_type VARCHAR(20) NOT NULL,
    UNIQUE(instance_id, message_id)
);