import { IconButton, Tooltip, useTheme } from '@mui/material';
import DarkModeIcon from '@mui/icons-material/DarkModeOutlined';
import LightModeIcon from '@mui/icons-material/LightModeOutlined';
import { useColorMode } from '../../theme/color-mode-context';

export default function ThemeToggle() {
    const { toggle } = useColorMode();
    const theme = useTheme();
    const isDark = theme.palette.mode === 'dark';

    return (
        <Tooltip title={isDark ? 'Light mode' : 'Dark mode'}>
            <IconButton
                onClick={toggle}
                size="small"
                sx={{
                    position: 'fixed',
                    top: 12,
                    left: 12,
                    zIndex: (t) => t.zIndex.tooltip + 1, // peste tot
                    bgcolor: 'background.paper',
                    border: '1px solid',
                    borderColor: 'divider',
                    boxShadow: 2,
                    backdropFilter: 'blur(6px)',
                    '&:hover': { bgcolor: 'action.hover' },
                }}
            >
                {isDark ? <LightModeIcon fontSize="small" /> : <DarkModeIcon fontSize="small" />}
            </IconButton>
        </Tooltip>
    );
}
