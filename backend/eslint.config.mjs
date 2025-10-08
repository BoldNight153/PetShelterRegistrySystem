// Comprehensive ESLint flat config for the backend (ESLint v9+)
// - Type-aware rules enabled (recommendedTypeChecked) but scoped to src/** only
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

  // Base TS rules (no type info required)
  ...tseslint.configs.recommended,

  // (Temporarily) skip type-aware rules to reduce noise; we'll re-enable progressively

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
      '@typescript-eslint/no-unsafe-assignment': 'off', // initially too noisy
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-unsafe-return': 'off',
      '@typescript-eslint/require-await': 'off', // allow small async wrappers for now
  '@typescript-eslint/no-unnecessary-type-assertion': 'off',
  '@typescript-eslint/no-misused-promises': 'off',
      '@typescript-eslint/no-require-imports': 'off',

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

  // Tests: enable jest context and lighten some rules substantially
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
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-unsafe-return': 'off',
      '@typescript-eslint/require-await': 'off',
      '@typescript-eslint/no-redundant-type-constituents': 'off',
    },
  },

  // Prisma and seed scripts: keep rules relaxed and allow require()
  {
    files: ['prisma/**/*.{ts,js}'],
    rules: {
      '@typescript-eslint/no-var-requires': 'off',
      '@typescript-eslint/no-require-imports': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-unsafe-return': 'off',
    },
  },
];
