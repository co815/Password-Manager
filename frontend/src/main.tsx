import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import AppThemeProvider from './theme/AppThemeProvider';
import './index.css';
import App from './App';

createRoot(document.getElementById('root')!).render(
    <StrictMode>
        <AppThemeProvider>
            <App />
        </AppThemeProvider>
    </StrictMode>
);
