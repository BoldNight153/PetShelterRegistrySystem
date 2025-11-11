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

// Minimal transport interface we need from nodemailer
type EmailSendResult = { messageId: string };
type EmailTransport = { sendMail: (opts: MailOptions & { from?: string }) => Promise<EmailSendResult> };

// Create a transporter based on env; fallback to a dev JSON/console logger
export function createTransport(): EmailTransport {
  const host = getEnv('SMTP_HOST');
  const portStr = getEnv('SMTP_PORT');
  const user = getEnv('SMTP_USER');
  const pass = getEnv('SMTP_PASS');
  const secure = getEnv('SMTP_SECURE', 'false') === 'true';

  if (host && portStr) {
    const port = Number(portStr);
    const real = nodemailer.createTransport({
      host,
      port,
      secure,
      auth: user && pass ? { user, pass } : undefined,
    });
    // Wrap the real transporter in a minimal, well-typed adapter so callers
    // only see the small sendMail API we need and we avoid returning
    // nodemailer's complex union types directly.
    return {
      sendMail: async (opts: MailOptions & { from?: string }) => {
  const info: unknown = await (real as any).sendMail(opts);
  // nodemailer returns varying info shapes depending on transport; prefer messageId when present
  const maybeMsg = info ? (info as any).messageId ?? undefined : undefined;
  const messageId = maybeMsg || `smtp-${Date.now()}`;
        return { messageId };
      },
    };
  }

  // Dev fallback: log emails to console/JSON and return a stable shape
  return {
    sendMail(opts: MailOptions & { from?: string }) {
      const payload = {
        transport: 'dev-console',
        to: opts.to,
        subject: opts.subject,
        text: opts.text,
        html: opts.html,
        from: opts.from,
      };

      console.info('[dev-email]', JSON.stringify(payload, null, 2));
      return Promise.resolve({ messageId: `dev-${Date.now()}` });
    },
  };
}

export async function sendMail(opts: MailOptions): Promise<EmailSendResult> {
  const from = getEnv('EMAIL_FROM') || 'no-reply@localhost';
  const transporter = createTransport();
  // Return a stable EmailSendResult shape so callers can rely on messageId
  return await transporter.sendMail({ from, ...opts });
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
