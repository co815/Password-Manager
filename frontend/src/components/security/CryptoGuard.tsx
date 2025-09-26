import { useLocation } from 'react-router-dom';
import { useAuth } from '../../auth/auth-context';
import { useCrypto } from '../../lib/crypto/crypto-context';
import UnlockDialog from './UnlockDialog';

export default function CryptoGuard() {
    const { locked, hadDek } = useCrypto();
    const { user, loggingOut } = useAuth();
    const { pathname } = useLocation();
    const open = locked && hadDek && !!user && !loggingOut && pathname !== '/';
    return <UnlockDialog open={open} />;
}
