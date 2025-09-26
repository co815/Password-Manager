import { useLocation } from 'react-router-dom';
import { useAuth } from '../../auth/auth-context';
import { useCrypto } from '../../lib/crypto/crypto-context';
import UnlockDialog from './UnlockDialog';

export default function CryptoGuard() {
    const { locked } = useCrypto();
    const { user, loggingOut } = useAuth();
    const { pathname } = useLocation();
    const open = locked && !!user && !loggingOut && pathname !== '/';
    return <UnlockDialog open={open} />;
}
