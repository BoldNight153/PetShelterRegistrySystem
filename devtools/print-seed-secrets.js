const crypto = require('crypto');

const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function deriveBase32Secret(seed) {
  const hash = crypto.createHash('sha256').update(`psrs:${seed}`).digest('hex');
  let secret = '';
  for (let i = 0; i < hash.length && secret.length < 32; i += 2) {
    const byte = parseInt(hash.slice(i, i + 2), 16);
    secret += alphabet[byte % alphabet.length];
  }
  return (secret + 'A'.repeat(32)).slice(0, 32);
}

const label = 'Seed Authenticator App';
const users = process.argv.slice(2);

if (users.length === 0) {
  console.error('Usage: node devtools/print-seed-secrets.js <email> [email...]');
  process.exit(1);
}

for (const email of users) {
  const secret = deriveBase32Secret(`${email}:${label}`);
  console.log(`${email}: ${secret}`);
}
