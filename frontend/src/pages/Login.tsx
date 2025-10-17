// src/pages/Login.tsx
import { Auth } from '@supabase/auth-ui-react';
import { ThemeSupa } from '@supabase/auth-ui-shared';
import { supabase } from '../supabaseClient';
import { useAuth } from '../contexts/AuthContext';
import { Navigate } from 'react-router-dom';

// A nossa nova página de Login.
const Login = () => {
  const { session } = useAuth();

  // Se o usuário já estiver logado (ou seja, já existe uma sessão),
  // redireciona ele para o Dashboard. Não faz sentido mostrar a página de login novamente.
  if (session) {
    return <Navigate to="/" replace />;
  }

  // Se não há sessão, renderizamos o componente de Auth UI do Supabase.
  // Este componente lida com login, cadastro, e recuperação de senha.
  return (
    <div style={{ maxWidth: '420px', margin: '96px auto' }}>
        <Auth
          supabaseClient={supabase}
          appearance={{ theme: ThemeSupa }}
          providers={['google', 'github']} // Opcional: adicione provedores OAuth que você configurou no Supabase
          theme="dark"
        />
    </div>
  );
};

export default Login;