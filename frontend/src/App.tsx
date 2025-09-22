import { BrowserRouter as Router, Routes, Route, useLocation } from 'react-router-dom';
import { Container } from '@mui/material';
import Home from './pages/Home';
import Dashboard from './pages/Dashboard';
import ProtectedRoute from './auth/ProtectedRoute';
import CryptoGuard from './components/security/CryptoGuard';
import LockButton from './components/security/LockButton';

function NotFound() {
    return <div>404: Page not found</div>;
}

function GlobalChrome() {
    const { pathname } = useLocation();
    return (
        <>
            {pathname !== '/' && <LockButton />}
            <CryptoGuard />
        </>
    );
}

export default function App() {
    return (
        <Router>
            <GlobalChrome />
            <Container maxWidth="lg">
                <Routes>
                    <Route path="/" element={<Home />} />
                    <Route element={<ProtectedRoute />}>
                        <Route path="/dashboard" element={<Dashboard />} />
                    </Route>
                    <Route path="*" element={<NotFound />} />
                </Routes>
            </Container>
        </Router>
    );
}
