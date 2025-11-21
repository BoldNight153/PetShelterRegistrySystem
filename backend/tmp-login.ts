import request from 'supertest';
import app from './src/index';

(async () => {
  try {
    const agent = request.agent(app);
    const csrfRes = await agent.get('/auth/csrf');
    console.log('csrf status', csrfRes.status);
    const csrfToken = csrfRes.body?.csrfToken;
    const csrfCookie = (csrfRes.headers['set-cookie'] || []).find((c: string) => c.startsWith('csrfToken='));
    console.log('csrf token', csrfToken);
    console.log('csrf cookie', csrfCookie);
    const res = await agent
      .post('/auth/login')
      .set('x-csrf-token', csrfToken)
      .set('Cookie', csrfCookie ?? '')
      .send({ email: 'admin@example.com', password: 'Admin123!@#', deviceFingerprint: undefined, deviceName: 'Debug Device', devicePlatform: 'debug', trustThisDevice: true });
    console.log('login status', res.status);
    console.log('login body', res.body);
  } catch (err) {
    console.error(err);
  }
})();
