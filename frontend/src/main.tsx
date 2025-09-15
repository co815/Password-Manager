import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import AppThemeProvider from './theme/AppThemeProvider';
import AuthProvider from './auth/AuthContext';
import './index.css';
import App from './App';

createRoot(document.getElementById('root')!).render(
    <StrictMode>
        <AppThemeProvider>
            <AuthProvider>
                <App />
            </AuthProvider>
        </AppThemeProvider>
    </StrictMode>
);
