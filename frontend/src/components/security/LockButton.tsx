import { IconButton, Tooltip } from '@mui/material';
import LockIcon from '@mui/icons-material/Lock';
import { useCrypto } from '../../lib/crypto/crypto-context';

export default function LockButton() {
    const { lockNow } = useCrypto();
    return (
        <Tooltip title="Lock now">
            <IconButton
                onClick={lockNow}
                size="small"
                sx={{
                    position: 'fixed',
                    top: 12,
                    right: 12,
                    zIndex: (t) => t.zIndex.tooltip + 1,
                    bgcolor: 'background.paper',
                    border: '1px solid',
                    borderColor: 'divider',
                    boxShadow: 2,
                    backdropFilter: 'blur(6px)',
                    '&:hover': { bgcolor: 'action.hover' },
                }}
            >
                <LockIcon fontSize="small" />
            </IconButton>
        </Tooltip>
    );
}
