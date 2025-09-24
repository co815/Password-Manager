import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from './auth-context';
import { isAuditAdminEmail } from '../lib/accessControl';

export default function AuditLogRoute() {
    const { user, loading } = useAuth();

    if (loading) return null;
    if (!user) return <Navigate to="/" replace />;

    const allowed = isAuditAdminEmail(user.email);
    return allowed ? <Outlet /> : <Navigate to="/dashboard" replace />;
}