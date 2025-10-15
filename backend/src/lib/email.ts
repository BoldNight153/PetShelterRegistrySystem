import nodemailer from 'nodemailer';

export type MailOptions = {
  to: string;
  subject: string;
  html?: string;
  text?: string;
};

function getEnv(name: string, fallback?: string): string | undefined {
  const v = process.env[name];
  if (v == null || v === '') return fallback;
  return v;
}

// Create a transporter based on env; fallback to a dev JSON/console logger
export function createTransport() {
  const host = getEnv('SMTP_HOST');
  const portStr = getEnv('SMTP_PORT');
  const user = getEnv('SMTP_USER');
  const pass = getEnv('SMTP_PASS');
  const secure = getEnv('SMTP_SECURE', 'false') === 'true';

  if (host && portStr) {
    const port = Number(portStr);
    return nodemailer.createTransport({
      host,
      port,
      secure,
      auth: user && pass ? { user, pass } : undefined,
    } as any);
  }

  // Dev fallback: log emails to console/JSON
  return {
    async sendMail(opts: any) {
      const payload = {
        transport: 'dev-console',
        to: opts.to,
        subject: opts.subject,
        text: opts.text,
        html: opts.html,
      };
      // eslint-disable-next-line no-console
      console.info('[dev-email]', JSON.stringify(payload, null, 2));
      return { messageId: `dev-${Date.now()}` } as any;
    },
  } as any;
}

export async function sendMail(opts: MailOptions) {
  const from = getEnv('EMAIL_FROM') || 'no-reply@localhost';
  const transporter = createTransport();
  return transporter.sendMail({ from, ...opts });
}

export function verificationEmailTemplate(params: { verifyUrl: string }) {
  const { verifyUrl } = params;
  const text = `Verify your email\n\nClick the link to verify your email address:\n${verifyUrl}\n\nIf you did not request this, you can ignore this email.`;
  const html = `
    <h1>Verify your email</h1>
    <p>Click the link to verify your email address:</p>
    <p><a href="${verifyUrl}">${verifyUrl}</a></p>
    <p>If you did not request this, you can ignore this email.</p>
  `;
  return { text, html };
}

export function resetPasswordEmailTemplate(params: { resetUrl: string }) {
  const { resetUrl } = params;
  const text = `Reset your password\n\nClick the link to reset your password:\n${resetUrl}\n\nIf you did not request this, you can ignore this email.`;
  const html = `
    <h1>Reset your password</h1>
    <p>Click the link to reset your password:</p>
    <p><a href="${resetUrl}">${resetUrl}</a></p>
    <p>If you did not request this, you can ignore this email.</p>
  `;
  return { text, html };
}
