import { createContext, useContext } from 'react';
import type { PaletteMode } from '@mui/material';

export type ColorModeContextValue = { mode: PaletteMode; toggle: () => void };

export const ColorModeContext = createContext<ColorModeContextValue>({
    mode: 'dark',
    toggle: () => {},
});

export const useColorMode = () => useContext(ColorModeContext);