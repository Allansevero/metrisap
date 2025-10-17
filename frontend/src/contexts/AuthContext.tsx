// src/contexts/AuthContext.tsx
import React, { createContext, useContext, useEffect, useState } from 'react';
import { Session, User } from '@supabase/supabase-js';
import { supabase } from '../supabaseClient';

// Define o tipo para o valor do nosso contexto de autenticação
type AuthContextType = {
  session: Session | null;
  user: User | null;
  loading: boolean;
};

// Cria o Context com um valor padrão.
// O valor será fornecido pelo AuthProvider.
const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Cria o nosso Provedor de Autenticação.
// Este componente irá envolver as partes da nossa aplicação que precisam saber sobre o estado de autenticação.
export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [session, setSession] = useState<Session | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Tenta obter a sessão atual do Supabase quando o componente é montado.
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session);
      setUser(session?.user ?? null);
      setLoading(false);
    });

    // Escuta por mudanças no estado de autenticação (LOGIN, LOGOUT, etc.).
    // O Supabase gerencia a sessão e o token no localStorage automaticamente.
    const { data: authListener } = supabase.auth.onAuthStateChange(
      (_event, session) => {
        setSession(session);
        setUser(session?.user ?? null);
        setLoading(false);
      }
    );

    // Função de limpeza: remove o listener quando o componente é desmontado.
    return () => {
      authListener?.subscription.unsubscribe();
    };
  }, []);

  // O valor que será compartilhado com os componentes filhos.
  const value = {
    session,
    user,
    loading,
  };

  // Renderiza os componentes filhos dentro do provedor de contexto.
  // O `!loading` garante que não vamos renderizar as rotas da aplicação
  // antes de sabermos se o usuário está logado ou não.
  return (
    <AuthContext.Provider value={value}>
      {!loading && children}
    </AuthContext.Provider>
  );
};

// Hook customizado para facilitar o uso do nosso contexto de autenticação.
// Em vez de importar useContext e AuthContext em cada componente,
// podemos simplesmente chamar useAuth().
export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};