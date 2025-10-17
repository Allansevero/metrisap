-- Adiciona a coluna supabase_user_id na tabela users
ALTER TABLE users ADD COLUMN IF NOT EXISTS supabase_user_id VARCHAR(255);
