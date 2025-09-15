import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { Container } from '@mui/material';
import Home from './pages/Home';
import Dashboard from './pages/Dashboard';
import ProtectedRoute from './auth/ProtectedRoute';

export default function App() {
    return (
        <Router>
            <Container maxWidth="lg">
                <Routes>
                    <Route path="/" element={<Home />} />
                    <Route element={<ProtectedRoute />}>
                        <Route path="/dashboard" element={<Dashboard />} />
                    </Route>
                    <Route path="*" element={<Home />} />
                </Routes>
            </Container>
        </Router>
    );
}
