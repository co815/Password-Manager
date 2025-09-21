import { useLocation } from 'react-router-dom';
import { useAuth } from '../../auth/AuthContext';
import { useCrypto } from '../../lib/crypto/CryptoContext';
import UnlockDialog from './UnlockDialog';

export default function CryptoGuard() {
    const { locked } = useCrypto();
    const { user } = useAuth();
    const { pathname } = useLocation();
    const open = locked && !!user && pathname !== '/';
    return <UnlockDialog open={open} />;
}
