import { defineConfig, type UserConfig } from 'vite';
import react from '@vitejs/plugin-react';
import type { UserConfig as VitestUserConfig } from 'vitest/config';

type ViteWithVitestConfig = UserConfig & { test: VitestUserConfig['test'] };

const config = {
    plugins: [react()],
    server: {
        proxy: {
            '/api': {
                target: 'https://localhost:8443',
                changeOrigin: true,
                secure: false,
            },
        },
    },
    test: {
        environment: 'jsdom',
        setupFiles: ['./src/test/setup.ts'],
    },
} satisfies ViteWithVitestConfig;

export default defineConfig(config);
