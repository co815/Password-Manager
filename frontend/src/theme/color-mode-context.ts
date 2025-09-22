import { createContext, useContext } from 'react';
import type { PaletteMode } from '@mui/material';

export type ColorModeContextValue = { mode: PaletteMode; toggle: () => void };

export const STORAGE_KEY = 'pm-ui-mode';

export function getInitialMode(): PaletteMode {
    if (typeof window === 'undefined') return 'light';
    const saved = localStorage.getItem(STORAGE_KEY) as PaletteMode | null;
    if (saved === 'light' || saved === 'dark') return saved;
    return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

export const ColorModeContext = createContext<ColorModeContextValue>({
    mode: 'light',
    toggle: () => {},
});

export const useColorMode = () => useContext(ColorModeContext);