import React from 'react';
import { AppBar, Toolbar, Typography, Button, Box, Container } from '@mui/material';
import { Link as RouterLink, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { supabase } from '../supabaseClient'; // Importar o cliente supabase
import DashboardIcon from '@mui/icons-material/Dashboard';
import StorageIcon from '@mui/icons-material/Storage';
import LogoutIcon from '@mui/icons-material/Logout';
import DescriptionIcon from '@mui/icons-material/Description';
import WhatsAppIcon from '@mui/icons-material/WhatsApp';

const Navbar: React.FC = () => {
  // Usamos a sessão do nosso novo hook de autenticação
  const { session } = useAuth();
  const location = useLocation();

  // A nova função de logout chama o método signOut do Supabase
  const handleLogout = async () => {
    const { error } = await supabase.auth.signOut();
    if (error) {
      console.error('Error logging out:', error);
    }
    // O AuthContext irá detectar a mudança de estado e o ProtectedRoute fará o redirecionamento.
  };

  // Se não houver sessão, não renderizamos a barra de navegação.
  if (!session) {
    return null;
  }

  const isActive = (path: string) => location.pathname === path;

  return (
    <AppBar 
      position="sticky" 
      elevation={0}
      sx={{ 
        bgcolor: '#202c33',
        borderBottom: '1px solid',
        borderColor: '#374045',
      }}
    >
      <Container
        maxWidth={false}
        sx={{
          maxWidth: {
            lg: '1200px',
            xl: '1400px'
          }
        }}
      >
        <Toolbar disableGutters>
          <Box sx={{ display: 'flex', alignItems: 'center', mr: 3 }}>
            <WhatsAppIcon sx={{ color: '#00a884', fontSize: 32, mr: 1 }} />
            <Typography 
              variant="h6" 
              component={RouterLink} 
              to="/"
              sx={{ 
                color: '#e9edef',
                textDecoration: 'none',
                fontWeight: 500,
                letterSpacing: '0.5px',
              }}
            >
              WuzAPI
            </Typography>
          </Box>

          <Box sx={{ display: 'flex', gap: 1 }}>
            <Button
              component={RouterLink}
              to="/"
              startIcon={<DashboardIcon />}
              sx={{
                color: isActive('/') ? '#00a884' : '#8696a0',
                '&:hover': {
                  color: '#00a884',
                },
                minWidth: '120px',
              }}
            >
              Dashboard
            </Button>
            <Button
              component={RouterLink}
              to="/instances"
              startIcon={<StorageIcon />}
              sx={{
                color: isActive('/instances') ? '#00a884' : '#8696a0',
                '&:hover': {
                  color: '#00a884',
                },
                minWidth: '120px',
              }}
            >
              Instâncias
            </Button>
            <Button
              component={RouterLink}
              to="/docs"
              startIcon={<DescriptionIcon />}
              sx={{
                color: isActive('/docs') ? '#00a884' : '#8696a0',
                '&:hover': {
                  color: '#00a884',
                },
                minWidth: '120px',
              }}
            >
              API Docs
            </Button>
          </Box>

          <Box sx={{ flexGrow: 1 }} />

          <Button
            onClick={handleLogout}
            startIcon={<LogoutIcon />}
            sx={{
              color: '#8696a0',
              '&:hover': {
                color: '#ea4335',
              },
            }}
          >
            Sair
          </Button>
        </Toolbar>
      </Container>
    </AppBar>
  );
};

export default Navbar; 