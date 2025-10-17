import { Navigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

// Este componente é um "guardião" para as nossas rotas.
const ProtectedRoute = ({ children }: { children: JSX.Element }) => {
  // Usamos nosso hook customizado para obter a sessão.
  const { session } = useAuth();

  // Se não houver uma sessão ativa, o usuário não está logado.
  // Então, o redirecionamos para a página de login.
  // O `replace` evita que a rota antiga fique no histórico do navegador.
  if (!session) {
    return <Navigate to="/login" replace />;
  }

  // Se houver uma sessão, o usuário está autorizado.
  // Renderizamos o componente filho que foi passado para a rota protegida.
  return children;
};

export default ProtectedRoute; 