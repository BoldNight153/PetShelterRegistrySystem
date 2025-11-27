const argon2 = require('argon2');
const hash = '$argon2id$v=19$m=65536,t=3,p=4$+8eui9X7j8yOy4HmES0yVw$qGTRq6INBOyPQXyIknzFWHMF4E9P7tx/5RQMHhABrO0';
(async () => {
  const ok = await argon2.verify(hash, 'Admin123!@#').catch(err => { console.error('verify err', err); return false; });
  console.log('verify', ok);
})();
