import type {Theme} from '@mui/material/styles';

export const gradientButtonBackground = 'linear-gradient(90deg, #2563eb 0%, #6366f1 50%, #7c3aed 100%)';

export const authButtonStyles = {
    py: 1.25,
    borderRadius: 3,
    fontWeight: 800,
    textTransform: 'none' as const,
    background: gradientButtonBackground,
    color: '#fff',
    boxShadow: '0 14px 32px rgba(129,140,248,0.38)',
    '&:hover': {background: gradientButtonBackground, opacity: 0.95},
    '&.Mui-disabled': {background: gradientButtonBackground, opacity: 0.55},
};

export const createFieldStyles = (theme: Theme) => ({
    '& .MuiOutlinedInput-root': {
        backgroundColor:
            theme.palette.mode === 'dark' ? 'rgba(15,23,42,0.55)' : 'rgba(255,255,255,0.93)',
        borderRadius: 2.5,
        color: theme.palette.mode === 'dark' ? '#f8fafc' : theme.palette.text.primary,
        boxShadow:
            theme.palette.mode === 'dark'
                ? '0 10px 30px rgba(15,23,42,0.55)'
                : '0 18px 38px rgba(79,70,229,0.18)',
        '& fieldset': {
            borderColor:
                theme.palette.mode === 'dark' ? 'rgba(148,163,184,0.45)' : 'rgba(125,140,255,0.4)',
        },
        '&:hover fieldset': {
            borderColor: theme.palette.mode === 'dark' ? 'rgba(129,140,248,0.75)' : 'rgba(99,102,241,0.7)',
        },
        '&.Mui-focused': {
            boxShadow:
                theme.palette.mode === 'dark'
                    ? '0 0 0 3px rgba(129,140,248,0.28)'
                    : '0 0 0 3px rgba(79,70,229,0.22)',
        },
        '&.Mui-focused fieldset': {
            borderColor: theme.palette.mode === 'dark' ? '#a5b4fc' : '#6366f1',
        },
        '& .MuiOutlinedInput-input': {
            color: theme.palette.mode === 'dark' ? '#f8fafc' : theme.palette.text.primary,
            fontWeight: 500,
        },
        '& .MuiSvgIcon-root': {
            color: theme.palette.mode === 'dark' ? '#c7d2fe' : '#4f46e5',
        },
        '& .MuiIconButton-root': {
            color: theme.palette.mode === 'dark' ? '#c7d2fe' : '#4f46e5',
        },
    },
    '& .MuiInputLabel-root': {
        color: theme.palette.mode === 'dark' ? 'rgba(226,232,240,0.75)' : 'rgba(30,41,59,0.7)',
        '&.Mui-focused': {
            color: theme.palette.mode === 'dark' ? '#c7d2fe' : '#4338ca',
        },
        fontWeight: 500,
    },
});