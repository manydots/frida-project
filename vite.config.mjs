import { fileURLToPath, URL } from 'node:url';
import { defineConfig, loadEnv } from 'vite';

export default defineConfig(({ mode }) => {
    const env = loadEnv(mode, process.cwd(), '');
    const { VITE_APP_MINIFY, VITE_APP_ENTRY } = env;

    return {
        server: {
            host: '0.0.0.0'
        },
        build: {
            target: 'es5',
            minify: JSON.parse(VITE_APP_MINIFY), // [true开启 false禁用]最小化混淆
            modulePreload: false,
            rollupOptions: {
                input: './src/main.ts',
                output: {
                    entryFileNames: VITE_APP_ENTRY,
                    assetFileNames: '[name]-[hash][extname]'
                }
            }
        },
        plugins: [],
        resolve: {
            alias: {
                '@': fileURLToPath(new URL('./src', import.meta.url))
            },
            extensions: ['.mjs', '.cjs', '.js', '.ts', '.jsx', '.tsx', '.json']
        }
    };
});
