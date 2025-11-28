import { defineConfig, type UserConfig } from 'vite';
import react from '@vitejs/plugin-react';
import type { InlineConfig } from 'vitest/node';
import path from 'path';

type ViteWithVitestConfig = UserConfig & { test: InlineConfig };

const config = {
    plugins: [react()],
    resolve: {
        alias: {
            '@': path.resolve(__dirname, './src'),
        },
    },
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
        environment: 'happy-dom',
        setupFiles: ['./src/test/setup.ts'],
    },
} satisfies ViteWithVitestConfig;

export default defineConfig(config);
