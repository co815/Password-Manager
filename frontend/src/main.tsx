import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import AppThemeProvider from './theme/AppThemeProvider';
import AuthProvider from './auth/AuthContext';
import CryptoProvider from './lib/crypto/CryptoContext';
import './index.css';
import App from './App';

createRoot(document.getElementById('root')!).render(
    <StrictMode>
        <AppThemeProvider>
            <AuthProvider>
                <CryptoProvider>
                    <App />
                </CryptoProvider>
            </AuthProvider>
        </AppThemeProvider>
    </StrictMode>
);
