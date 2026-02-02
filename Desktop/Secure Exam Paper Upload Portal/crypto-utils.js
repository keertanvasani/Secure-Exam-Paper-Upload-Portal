import crypto from 'crypto';

// Crypto utilities for secure exam paper handling

//PASSWORD HASHING

// Generate random salt
export function generateSalt() {
  return crypto.randomBytes(16).toString('hex');
}

// Hash password with salt
export function hashPassword(password, salt) {
  return crypto.createHash('sha256').update(password + salt).digest('hex');
}

// Verify password
export function verifyPassword(password, salt, hash) {
  return hashPassword(password, salt) === hash;
}

//RSA KEY GENERATION

// Generate RSA-2048 key pair
export function generateRSAKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  return { publicKey, privateKey };
}

//AES ENCRYPTION

// Generate AES-256 key
export function generateAESKey() {
  return crypto.randomBytes(32);
}

// Encrypt file using AES-256-GCM
export function encryptFile(fileBuffer, aesKey) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);

  const encryptedData = Buffer.concat([
    cipher.update(fileBuffer),
    cipher.final()
  ]);

  return {
    encryptedData,
    iv,
    authTag: cipher.getAuthTag()
  };
}

// Decrypt file using AES-256-GCM
export function decryptFile(encryptedData, aesKey, iv, authTag) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
  decipher.setAuthTag(authTag);

  return Buffer.concat([
    decipher.update(encryptedData),
    decipher.final()
  ]);
}

//RSA KEY EXCHANGE

// Encrypt AES key using RSA public key
export function encryptAESKey(aesKey, publicKey) {
  return crypto.publicEncrypt(
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    aesKey
  );
}

// Decrypt AES key using RSA private key
export function decryptAESKey(encryptedKey, privateKey) {
  return crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    encryptedKey
  );
}

//DIGITAL SIGNATURES

// Sign data
export function signData(data, privateKey) {
  const sign = crypto.createSign('SHA256');
  sign.update(data);
  sign.end();
  return sign.sign(privateKey, 'base64');
}

// Verify signature
export function verifySignature(data, signature, publicKey) {
  const verify = crypto.createVerify('SHA256');
  verify.update(data);
  verify.end();
  return verify.verify(publicKey, signature, 'base64');
}

//BASE64 HELPERS

export function encodeBase64(buffer) {
  return buffer.toString('base64');
}

export function decodeBase64(base64String) {
  return Buffer.from(base64String, 'base64');
}

//COMPLETE WORKFLOW

// Encrypt exam paper
export function encryptExamPaper(fileBuffer, filename) {
  const { publicKey, privateKey } = generateRSAKeyPair();
  const aesKey = generateAESKey();

  const { encryptedData, iv, authTag } = encryptFile(fileBuffer, aesKey);
  const encryptedAESKey = encryptAESKey(aesKey, publicKey);
  const signature = signData(fileBuffer, privateKey);

  return {
    encryptedData: encodeBase64(encryptedData),
    iv: encodeBase64(iv),
    authTag: encodeBase64(authTag),
    encryptedAESKey: encodeBase64(encryptedAESKey),
    publicKey,
    privateKey,
    signature,
    originalFilename: filename
  };
}

// Decrypt exam paper
export function decryptExamPaper(encryptedPaper) {
  const encryptedData = decodeBase64(encryptedPaper.encryptedData);
  const iv = decodeBase64(encryptedPaper.iv);
  const authTag = decodeBase64(encryptedPaper.authTag);
  const encryptedAESKey = decodeBase64(encryptedPaper.encryptedAESKey);

  const aesKey = decryptAESKey(encryptedAESKey, encryptedPaper.privateKey);
  return decryptFile(encryptedData, aesKey, iv, authTag);
}

// Generate 6-digit OTP
export function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}
