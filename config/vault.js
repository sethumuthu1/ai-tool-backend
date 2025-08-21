// vault.js
const dotenv = require('dotenv');
const vault = require('node-vault')({
  endpoint: process.env.VAULT_ADDR,
  token: process.env.VAULT_TOKEN,
});

async function getSecretsFromVault() {
  try {
    const secrets = await vault.read('secret/data/ai-secrets'); // adjust path if needed
    const data = secrets.data.data;

    // Set secrets to environment
    process.env.JWT_SECRET = data.JWT_SECRET;
    process.env.DB_USER = data.DB_USER;
    process.env.DB_PASSWORD = data.DB_PASSWORD;
    process.env.EMAIL_USER = data.EMAIL_USER;
    process.env.EMAIL_PASSWORD = data.EMAIL_PASSWORD;

    console.log('✅ Vault secrets loaded');
  } catch (err) {
    console.error('❌ Error loading secrets from Vault:', err.message || err);
    throw err;
  }
}

module.exports = { getSecretsFromVault };
