// Comprehensive ESLint flat config for the backend (ESLint v9+)
// - Type-aware rules enabled (recommendedTypeChecked)
// - Plugins: import, promise, security, sonarjs, unicorn, jest, stylistic
// - Prettier is expected to handle formatting; Stylistic covers stylistic nits Prettier doesn't

import tseslint from 'typescript-eslint';
import importPlugin from 'eslint-plugin-import';
import promisePlugin from 'eslint-plugin-promise';
import securityPlugin from 'eslint-plugin-security';
import sonarjs from 'eslint-plugin-sonarjs';
import unicorn from 'eslint-plugin-unicorn';
import jestPlugin from 'eslint-plugin-jest';
import stylistic from '@stylistic/eslint-plugin';

export default [
  // Ignore build artifacts and vendor
  { ignores: ['dist/**', 'node_modules/**'] },

  // Base TS rules
  ...tseslint.configs.recommended,

  // Type-aware rules (uses Project Service; no need to point to tsconfig explicitly)
  ...tseslint.configs.recommendedTypeChecked.map((cfg) => ({
    ...cfg,
    languageOptions: {
      ...cfg.languageOptions,
      parserOptions: {
        ...(cfg.languageOptions?.parserOptions ?? {}),
        projectService: true,
      },
    },
  })),

  // Global plugin rules
  {
    plugins: {
      import: importPlugin,
      promise: promisePlugin,
      security: securityPlugin,
      sonarjs,
      unicorn,
      jest: jestPlugin,
      '@stylistic': stylistic,
    },
    rules: {
      // TypeScript tweaks
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      '@typescript-eslint/no-explicit-any': 'off', // relax while migrating; tighten later
      '@typescript-eslint/no-unsafe-assignment': 'off', // too noisy initially
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',

      // import/promise/security/sonarjs/unicorn
      'import/no-unresolved': 'off', // TS handles this; avoids resolver setup
      'promise/catch-or-return': 'warn',
      'security/detect-object-injection': 'off',
      'sonarjs/no-duplicate-string': 'warn',
      'unicorn/prevent-abbreviations': 'off',
      'unicorn/filename-case': 'off',

      // stylistic nits Prettier won't enforce
      '@stylistic/quotes': ['warn', 'single', { avoidEscape: true }],
      '@stylistic/semi': ['warn', 'always'],
      '@stylistic/no-trailing-spaces': 'warn',
    },
  },

  // Tests: enable jest context and lighten some rules
  {
    files: ['src/tests/**/*.ts'],
    plugins: { jest: jestPlugin },
    languageOptions: {
      globals: {
        jest: true,
        describe: true,
        it: true,
        expect: true,
        beforeAll: true,
        afterAll: true,
        beforeEach: true,
        afterEach: true,
      },
    },
    rules: {
      'jest/expect-expect': 'off',
    },
  },

  // Prisma and seed scripts: keep rules relaxed
  {
    files: ['prisma/**/*.{ts,js}'],
    rules: {
      '@typescript-eslint/no-var-requires': 'off',
      '@typescript-eslint/no-require-imports': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
    },
  },
];
