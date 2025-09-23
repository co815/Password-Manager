import { useMemo } from 'react';
import type { PropsWithChildren } from 'react';
import { createTheme, responsiveFontSizes, ThemeProvider } from '@mui/material/styles';
import type { PaletteMode, ThemeOptions } from '@mui/material';
import CssBaseline from '@mui/material/CssBaseline';

import { ColorModeContext, type ColorModeContextValue } from './color-mode-context';

function getDesignTokens(mode: PaletteMode): ThemeOptions {
    const isDark = mode === 'dark';
    return {
        palette: {
            mode,
            primary: { main: '#6366f1' },
            secondary: { main: '#06b6d4' },
            background: {
                default: isDark ? '#0b1020' : '#f7f9ff',
                paper:   isDark ? '#11172b' : '#ffffff',
            },
        },
        shape: { borderRadius: 16 },
        typography: {
            fontFamily: `'Inter', system-ui, -apple-system, 'Segoe UI', Roboto, Arial, sans-serif`,
            h6: { fontWeight: 800, letterSpacing: 0.4 },
            button: { textTransform: 'none', fontWeight: 700 },
        },
        components: {
            MuiPaper: {
                styleOverrides: {
                    root: {
                        borderRadius: 16,
                        boxShadow: isDark
                            ? '0 10px 40px rgba(0,0,0,.35)'
                            : '0 10px 40px rgba(31,41,55,.10)',
                    },
                },
            },
            MuiButton: {
                styleOverrides: {
                    containedPrimary: {
                        background: 'linear-gradient(90deg,#2563eb 0%,#6366f1 50%,#7c3aed 100%)',
                        color: '#fff',
                        boxShadow: '0 8px 24px rgba(99,102,241,.25)',
                        '&:hover': { opacity: .95, boxShadow: '0 10px 28px rgba(99,102,241,.35)' },
                        '&:active': { transform: 'translateY(1px)' },
                    },
                },
            },
            MuiOutlinedInput: {
                styleOverrides: {
                    root: {
                        '&.Mui-focused .MuiOutlinedInput-notchedOutline': { borderColor: '#6366f1' },
                    },
                },
            },
            MuiTabs: {
                styleOverrides: {
                    indicator: { height: 4, borderRadius: 2, background: 'linear-gradient(90deg,#2563eb,#7c3aed)' },
                },
            },
            MuiTab: {
                styleOverrides: { root: { fontWeight: 700 } },
            },
        },
    };
}

export default function AppThemeProvider({ children }: PropsWithChildren) {

    const theme = useMemo(
        () => responsiveFontSizes(createTheme(getDesignTokens('dark'))),
        []
    );

    const value = useMemo<ColorModeContextValue>(
        () => ({ mode: 'dark', toggle: () => {} }),
        []
    );

    return (
        <ColorModeContext.Provider value={value}>
            <ThemeProvider theme={theme}>
                <CssBaseline />
                {children}
            </ThemeProvider>
        </ColorModeContext.Provider>
    );
}
