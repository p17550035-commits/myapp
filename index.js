// Password generator & encrypted vault
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const { URL } = require('url');
const querystring = require('querystring');

const PORT = process.env.PORT || 3000;
const VAULT_FILE = './vault.enc';
const VAULT_KEY_HEX = process.env.VAULT_KEY; // expect 32-byte hex string
let vaultKey;
if (!VAULT_KEY_HEX) {
  // Generate a random key and instruct user to set it
  const randomKey = crypto.randomBytes(32).toString('hex');
  console.error(`VAULT_KEY not set. For persistent encryption, set VAULT_KEY=${randomKey}`);
  // For demo, fallback to a fixed key (NOT secure for production)
  vaultKey = crypto.createHash('sha256').update('default-insecure-key-change-me').digest();
} else {
  vaultKey = Buffer.from(VAULT_KEY_HEX, 'hex');
  if (vaultKey.length !== 32) {
    console.error('VAULT_KEY must be 32 bytes (64 hex characters). Using fallback.');
    vaultKey = crypto.createHash('sha256').update('default-insecure-key-change-me').digest();
  }
}

// Helper: encrypt text, returns { iv: hex, encrypted: hex, tag: hex }
function encrypt(text) {
  const iv = crypto.randomBytes(12); // GCM recommended IV length
  const cipher = crypto.createCipheriv('aes-256-gcm', vaultKey, iv);
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString('hex'),
    encrypted: encrypted.toString('hex'),
    tag: tag.toString('hex')
  };
}

// Helper: decrypt object
function decrypt({ iv, encrypted, tag }) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', vaultKey, Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(tag, 'hex'));
  const decrypted = Buffer.concat([decipher.update(Buffer.from(encrypted, 'hex'), 'hex'), decipher.final()]);
  return decrypted.toString('utf8');
}

// Load vault from file
function loadVault() {
  if (!fs.existsSync(VAULT_FILE)) return [];
  try {
    const data = fs.readFileSync(VAULT_FILE, 'utf8');
    const parsed = JSON.parse(data);
    // Ensure each entry has iv,encrypted,tag
    return parsed.map(entry => ({
      id: entry.id,
      type: entry.type,
      ...entry
    }));
  } catch (e) {
    console.error('Failed to load vault:', e);
    return [];
  }
}

// Save vault to file
function saveVault(vault) {
  const toStore = vault.map(({ id, type, iv, encrypted, tag }) => ({
    id,
    type,
    iv,
    encrypted,
    tag
  }));
  fs.writeFileSync(VAULT_FILE, JSON.stringify(toStore, null, 2));
}

let vault = loadVault();

// Generate a random password
function generatePassword(length = 16) {
  const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+~`|}{[]:;?><,./-=' ;
  let pass = '';
  for (let i = 0; i < length; i++) {
    const idx = crypto.randomInt(0, charset.length);
    pass += charset[idx];
  }
  return pass;
}

const server = http.createServer(async (req, res) => {
  const { pathname, searchParams } = new URL(req.url, `http://${req.headers.host}`);
  const method = req.method;

  // Simple CORS for local testing (optional)
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // Home
  if (method === 'GET' && pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(`Password Generator & Vault API\n
Endpoints:
 GET  /generate?length=12          -> generate password
 POST /vault/add   {type,value}    -> store encrypted entry
 GET  /vault/list               -> list stored entries (ids, types)
 GET  /vault/get?id=<id>        -> decrypt and return value
Set environment variable VAULT_KEY (32-byte hex) for persistent encryption.
`);
    return;
  }

  // Generate password
  if (method === 'GET' && pathname === '/generate') {
    const length = parseInt(searchParams.get('length')) || 16;
    if (isNaN(length) || length < 1 || length > 1024) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid length' }));
      return;
    }
    const pass = generatePassword(length);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ password: pass }));
    return;
  }

  // Vault add
  if (method === 'POST' && pathname === '/vault/add') {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    req.on('end', () => {
      let payload;
      try {
        payload = JSON.parse(body);
      } catch (_) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON' }));
        return;
      }
      const { type, value } = payload;
      if (!type || !['api_key', 'email'].includes(type)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: "type must be 'api_key' or 'email'" }));
        return;
      }
      if (typeof value !== 'string' || value.length === 0) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'value must be a non-empty string' }));
        return;
      }
      const enc = encrypt(value);
      const id = crypto.randomBytes(4).toString('hex'); // 8-char hex id
      vault.push({ id, type, ...enc });
      saveVault(vault);
      res.writeHead(201, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ id, type }));
    });
    return;
  }

  // Vault list
  if (method === 'GET' && pathname === '/vault/list') {
    const list = vault.map(({ id, type }) => ({ id, type }));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(list));
    return;
  }

  // Vault get
  if (method === 'GET' && pathname === '/vault/get') {
    const id = searchParams.get('id');
    if (!id) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Missing id parameter' }));
      return;
    }
    const entry = vault.find(e => e.id === id);
    if (!entry) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Entry not found' }));
      return;
    }
    try {
      const plain = decrypt(entry);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ id: entry.id, type: entry.type, value: plain }));
    } catch (_) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Decryption failed' }));
    }
    return;
  }

  // Not found
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not found\n');
});

server.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}/`);
});
