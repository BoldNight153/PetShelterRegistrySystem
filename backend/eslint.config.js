// Minimal ESLint flat config for the backend (ESLint v9+)
// Goal: low-noise, TypeScript-aware lint to unblock "npm run lint".
// Future: expand with import/promise/security/sonarjs/unicorn/prettier, and type-aware rules.

import tseslint from 'typescript-eslint';

export default [
  // Ignore build artifacts, vendor, prisma scripts, and tests (for now)
  { ignores: ['dist/**', 'node_modules/**', 'prisma/**', 'src/tests/**'] },
  // Minimal recommended TypeScript rules
  ...tseslint.configs.recommended,
  {
    rules: {
      // Keep signal-to-noise high for now
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-var-requires': 'off',
      '@typescript-eslint/no-require-imports': 'off',
      // Allow intentionally unused via underscore prefix
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
    },
  },
  // TODO (future): add comprehensive rulesets
  // - import, promise, security, sonarjs, unicorn
  // - type-aware configs (recommendedTypeChecked)
  // - stylistic/prettier integration
];
