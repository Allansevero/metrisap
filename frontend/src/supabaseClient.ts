// src/supabaseClient.ts

import { createClient } from '@supabase/supabase-js';

// Obtém a URL e a chave anônima do Supabase a partir das variáveis de ambiente.
// O React (via Create React App) substitui process.env.REACT_APP_* em tempo de build.
const supabaseUrl = process.env.REACT_APP_SUPABASE_URL;
const supabaseAnonKey = process.env.REACT_APP_SUPABASE_ANON_KEY;

// Validação para garantir que as variáveis de ambiente foram configuradas.
if (!supabaseUrl || !supabaseAnonKey) {
  throw new Error("Supabase URL and Anon Key must be defined in your .env file");
}

// Cria e exporta a instância do cliente Supabase.
// Esta instância será usada em toda a aplicação para interagir com o Supabase (auth, db, etc.).
export const supabase = createClient(supabaseUrl, supabaseAnonKey);
