module.exports = {
  testEnvironment: 'node',
  transform: {
    '^.+\\.js$': [ 'babel-jest', { configFile: './babel.config.cjs' } ],
  },
  // Note: using babel-jest transform to support ESM-style imports in tests
}

