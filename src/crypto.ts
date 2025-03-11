import { webcrypto } from "crypto";

// #############
// ### Utils ###
// #############

// Function to convert ArrayBuffer to Base64 string
function arrayBufferToBase64(buffer: ArrayBuffer): string {
    return Buffer.from(buffer).toString("base64");
}

// Function to convert Base64 string to ArrayBuffer
function base64ToArrayBuffer(base64: string): ArrayBuffer {
    var buff = Buffer.from(base64, "base64");
    return buff.buffer.slice(buff.byteOffset, buff.byteOffset + buff.byteLength);
}

// ################
// ### RSA keys ###
// ################

// Generates a pair of private/public RSA keys.
type GenerateRsaKeyPair = {
    publicKey: webcrypto.CryptoKey;
    privateKey: webcrypto.CryptoKey;
};
export async function generateRsaKeyPair(): Promise<GenerateRsaKeyPair> {
    const keyPair = await webcrypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
    );
    return keyPair as GenerateRsaKeyPair;
}

// Export a public key to a Base64 string.
export async function exportPubKey(key: webcrypto.CryptoKey): Promise<string> {
    const spki = await webcrypto.subtle.exportKey("spki", key);
    return arrayBufferToBase64(spki);
}

// Export a private key to a Base64 string.
export async function exportPrvKey(key: webcrypto.CryptoKey | null): Promise<string | null> {
    if (!key) return null;
    const pkcs8 = await webcrypto.subtle.exportKey("pkcs8", key);
    return arrayBufferToBase64(pkcs8);
}

// Import a public key from its Base64 string representation.
export async function importPubKey(strKey: string): Promise<webcrypto.CryptoKey> {
    const binaryDer = base64ToArrayBuffer(strKey);
    return await webcrypto.subtle.importKey(
        "spki",
        binaryDer,
        {
            name: "RSA-OAEP",
            hash: "SHA-256",
        },
        true,
        ["encrypt"]
    );
}

// Import a private key from its Base64 string representation.
export async function importPrvKey(strKey: string): Promise<webcrypto.CryptoKey> {
    const binaryDer = base64ToArrayBuffer(strKey);
    return await webcrypto.subtle.importKey(
        "pkcs8",
        binaryDer,
        {
            name: "RSA-OAEP",
            hash: "SHA-256",
        },
        true,
        ["decrypt"]
    );
}

// Encrypt a base64-encoded message with an RSA public key.
export async function rsaEncrypt(
    b64Data: string,
    strPublicKey: string
): Promise<string> {
    const publicKey = await importPubKey(strPublicKey);
    const dataBuffer = base64ToArrayBuffer(b64Data);
    const encryptedBuffer = await webcrypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        dataBuffer
    );
    return arrayBufferToBase64(encryptedBuffer);
}

// Decrypt a base64-encoded message with an RSA private key.
export async function rsaDecrypt(
    data: string,
    privateKey: webcrypto.CryptoKey
): Promise<string> {
    const encryptedBuffer = base64ToArrayBuffer(data);
    const decryptedBuffer = await webcrypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        encryptedBuffer
    );
    return arrayBufferToBase64(decryptedBuffer);
}

// ######################
// ### Symmetric keys ###
// ######################

// Generate a random symmetric AES-CBC key.
export async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
    return await webcrypto.subtle.generateKey(
        { name: "AES-CBC", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

// Export a symmetric key to a Base64 string.
export async function exportSymKey(key: webcrypto.CryptoKey): Promise<string> {
    const raw = await webcrypto.subtle.exportKey("raw", key);
    return arrayBufferToBase64(raw);
}

// Import a symmetric key from its Base64 string representation.
export async function importSymKey(strKey: string): Promise<webcrypto.CryptoKey> {
    const raw = base64ToArrayBuffer(strKey);
    return await webcrypto.subtle.importKey(
        "raw",
        raw,
        { name: "AES-CBC" },
        true,
        ["encrypt", "decrypt"]
    );
}

// Encrypt a message using a symmetric key.
// The result includes the IV and ciphertext separated by a colon.
export async function symEncrypt(
    key: webcrypto.CryptoKey,
    data: string
): Promise<string> {
    const iv = webcrypto.getRandomValues(new Uint8Array(16));
    const encoder = new TextEncoder();
    const encodedData = encoder.encode(data);
    const encryptedBuffer = await webcrypto.subtle.encrypt(
        { name: "AES-CBC", iv },
        key,
        encodedData
    );
    const ivBase64 = arrayBufferToBase64(iv.buffer.slice(iv.byteOffset, iv.byteOffset + iv.byteLength));
    const cipherBase64 = arrayBufferToBase64(encryptedBuffer);
    return ivBase64 + ":" + cipherBase64;
}

// Decrypt a message using a symmetric key.
// The input encryptedData should be in the format "iv:ciphertext".
export async function symDecrypt(
    strKey: string,
    encryptedData: string
): Promise<string> {
    const key = await importSymKey(strKey);
    const parts = encryptedData.split(":");
    if (parts.length !== 2) throw new Error("Invalid encrypted data format");
    const [ivBase64, cipherBase64] = parts;
    const ivArray = new Uint8Array(base64ToArrayBuffer(ivBase64));
    const cipherArrayBuffer = base64ToArrayBuffer(cipherBase64);
    const decryptedBuffer = await webcrypto.subtle.decrypt(
        { name: "AES-CBC", iv: ivArray },
        key,
        cipherArrayBuffer
    );
    const decoder = new TextDecoder();
    return decoder.decode(decryptedBuffer);
}
