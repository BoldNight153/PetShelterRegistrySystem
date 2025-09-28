// eslint.config.cjs - root ESLint configuration compatible with ESLint v8+ and v9+
const jsConfig = require('./app/.eslintrc.json');

module.exports = [
  // Base rules for JS files
  {
    files: ['**/*.js', '**/*.cjs', '**/*.mjs'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module'
    },
    ...jsConfig
  },

  // TypeScript specific config
  {
    files: ['**/*.ts', '**/*.tsx'],
    plugins: {
      '@typescript-eslint': require('@typescript-eslint/eslint-plugin')
    },
    languageOptions: {
      parser: '@typescript-eslint/parser',
      parserOptions: {
        project: './tsconfig.json'
      }
    },
    rules: {
      // recommended TypeScript rules
      '@typescript-eslint/no-unused-vars': ['warn'],
      '@typescript-eslint/explicit-module-boundary-types': 'off'
    }
  }
];
