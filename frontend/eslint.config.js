import js from '@eslint/js';
import ts from 'typescript-eslint';
import svelte from 'eslint-plugin-svelte';
import globals from 'globals';

export default ts.config(
    {
        ignores: [
            'build/',
            '.svelte-kit/',
            'dist/',
            'node_modules/',
            'src/lib/generated/', // ignore auto-generated API client files
            'scripts/', // ignore codegen/tooling scripts
        ],
    },
    js.configs.recommended,
    ...ts.configs.recommended,
    ...svelte.configs['flat/recommended'],
    {
        languageOptions: {
            globals: {
                ...globals.browser,
                ...globals.node,
                __APP_VERSION__: 'readonly',
            },
        },
    },
    {
        files: ['src/**/*.{ts,js,svelte}', 'test/**/*.ts'],
        languageOptions: {
            parserOptions: {
                parser: ts.parser,
                projectService: true,
                tsconfigRootDir: import.meta.dirname,
                extraFileExtensions: ['.svelte'],
            },
        },
    },
    {
        files: ['**/*.svelte'],
        languageOptions: {
            parserOptions: {
                parser: ts.parser,
            },
        },
    },
    {
        rules: {
            'no-unused-vars': 'off',
            '@typescript-eslint/no-unused-vars': [
                'warn',
                {
                    argsIgnorePattern: '^_',
                    varsIgnorePattern: '^_',
                    caughtErrorsIgnorePattern: '^_',
                },
            ],
            // Svelte 5 rune declaration styling rules
            'svelte/no-inner-declarations': 'off',
        },
    }
);
