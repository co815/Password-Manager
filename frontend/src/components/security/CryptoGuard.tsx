import { useLocation } from 'react-router-dom';
import { useAuth } from '../../auth/AuthContext';
import { useCrypto } from '../../lib/crypto/CryptoContext';
import UnlockDialog from './UnlockDialog';

export default function CryptoGuard() {
    const { locked } = useCrypto();
    const { token } = useAuth();
    const { pathname } = useLocation();
    const open = locked && !!token && pathname !== '/';
    return <UnlockDialog open={open} />;
}
