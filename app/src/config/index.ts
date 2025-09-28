interface Config {
  NODE_ENV: string;
  PORT: string | number;
  DATABASE_URL: string;
  SENTRY_DSN?: string;
  APP_NAME?: string;
}

const config: Config = {
  NODE_ENV: process.env.NODE_ENV || 'development',
  PORT: process.env.PORT || 3000,
  DATABASE_URL: process.env.DATABASE_URL || 'file:./dev.db',
  SENTRY_DSN: process.env.SENTRY_DSN || '',
  APP_NAME: process.env.APP_NAME || 'clean-app'
};

export default config;

// small no-op comment to test pre-commit hook
