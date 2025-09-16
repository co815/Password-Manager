import { useLocation } from 'react-router-dom';
import { useCrypto } from '../../lib/crypto/CryptoContext';
import UnlockDialog from './UnlockDialog';

export default function CryptoGuard() {
    const { locked, hadDek } = useCrypto();
    const { pathname } = useLocation();
    const open = locked && hadDek && pathname !== '/';
    return <UnlockDialog open={open} />;
}
