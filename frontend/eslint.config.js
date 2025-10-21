import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'
import { defineConfig, globalIgnores } from 'eslint/config'

// Add generated/build folders to the global ignore list so ESLint doesn't scan
// dependencies or Vite's pre-bundled files which can introduce false positives.
export default defineConfig([
  globalIgnores(['dist', '.vite', 'public', 'node_modules']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      reactHooks.configs['recommended-latest'],
      reactRefresh.configs.vite,
    ],
    // Temporary rule relaxations to reduce noisy failures during migration.
    // These should be tightened in follow-up PRs where code is cleaned up.
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      'react-refresh/only-export-components': 'off',
      'no-empty': ['error', { 'allowEmptyCatch': true }],
    },
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
    },
  },
])
