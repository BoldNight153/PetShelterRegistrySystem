const argon2 = require('argon2');
(async () => {
  try {
    const hash = '$argon2id$v=19$m=65536,t=3,p=4$uU1EZGUx/CaISUOp6h79tg$dlUMpaHlimK0BgaMsGPimOSj/8yu6cQdi1fbFtmlc5M';
    const ok = await argon2.verify(hash, 'Admin123!@#');
    console.log('match?', ok);
  } catch (err) {
    console.error(err);
  }
})();
