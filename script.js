// CAESAR CIPHER
function caesarCipher(str, shift, action) {
    let output = '';
    const adjust = action === 'encrypt' ? shift : -shift;

    for (let i = 0; i < str.length; i++) {
        let char = str[i];
        if (char.match(/[a-z]/i)) {
            const code = str.charCodeAt(i);
            let base = 'A'.charCodeAt(0);

            if (char == char.toLowerCase()) {
                base = 'a'.charCodeAt(0);
            }

            char = String.fromCharCode(((code - base + adjust) % 26 + 26) % 26 + base);
        }
        output += char;
    }
    return output;
}

function encryptText() {
    const inputText = document.getElementById('inputText').value;
    const shift = parseInt(document.getElementById('encryptShift').value);
    if (!isNaN(shift)) {
        const encryptedText = caesarCipher(inputText, shift, 'encrypt');
        document.getElementById('cipherText').value = encryptedText;
    }
}

function decryptText() {
    const cipherText = document.getElementById('cipherText').value;
    const shift = parseInt(document.getElementById('decryptShift').value);
    if (!isNaN(shift)) {
        const decryptedText = caesarCipher(cipherText, shift, 'decrypt');
        document.getElementById('resultText').value = decryptedText;
    }
}

document.getElementById('encryptShift').addEventListener('input', function() {
    encryptText();
    decryptText()
});
document.getElementById('inputText').addEventListener('input', function() {
    encryptText();
    decryptText()
});
document.getElementById('decryptShift').addEventListener('input', decryptText);
document.getElementById('cipherText').addEventListener('input', decryptText);

// ---

// AES
document.getElementById('generateKeyIv').addEventListener('click', async () => {
    const key = window.crypto.getRandomValues(new Uint8Array(16));
    const iv = window.crypto.getRandomValues(new Uint8Array(16));

    document.getElementById('key').value = Array.from(key).map(b => b.toString(16).padStart(2, '0'))
        .join('');
    document.getElementById('iv').value = Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join(
            '');
});

document.getElementById('encrypt').addEventListener('click', async () => {
    const plaintext = document.getElementById('plaintext').value;
    const keyHex = document.getElementById('key').value;
    const ivHex = document.getElementById('iv').value;

    const key = new Uint8Array(keyHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const iv = new Uint8Array(ivHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

    const cryptoKey = await window.crypto.subtle.importKey(
        'raw',
        key, {
            name: 'AES-CBC'
        },
        false,
        ['encrypt']
    );

    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);
    const paddedData = new Uint8Array(16 * Math.ceil(data.byteLength / 16));
    paddedData.set(data);

    const ciphertext = await window.crypto.subtle.encrypt({
            name: 'AES-CBC',
            iv
        },
        cryptoKey,
        paddedData
    );

    document.getElementById('ciphertext').value = btoa(String.fromCharCode(...new Uint8Array(
        ciphertext)));
});

document.getElementById('decrypt').addEventListener('click', async () => {
    const ciphertext = document.getElementById('ciphertext').value;
    const keyHex = document.getElementById('inputKey').value;
    const ivHex = document.getElementById('inputIv').value;

    if (keyHex.length !== 32 && keyHex.length !== 48 && keyHex.length !== 64) {
        alert('Invalid key length. AES key must be 128, 192, or 256 bits.');
        return;
    }

    const key = new Uint8Array(keyHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const iv = new Uint8Array(ivHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const ciphertextBytes = new Uint8Array(atob(ciphertext).split('').map(c => c.charCodeAt(0)));

    try {
        const cryptoKey = await window.crypto.subtle.importKey(
            'raw',
            key, {
                name: 'AES-CBC'
            },
            false,
            ['decrypt']
        );

        const decryptedData = await window.crypto.subtle.decrypt({
                name: 'AES-CBC',
                iv
            },
            cryptoKey,
            ciphertextBytes
        );

        const decoder = new TextDecoder();
        document.getElementById('decryptedtext').value = decoder.decode(decryptedData).replace(/\0/g,
            '');
    } catch (e) {
        const decoder = new TextDecoder();
        document.getElementById('decryptedtext').value = decoder.decode(ciphertextBytes).replace(/\0/g,
            '');
    }
});
document.getElementById('pasteKey').addEventListener('click', function() {
    document.getElementById('inputKey').value = document.getElementById('key').value
    document.getElementById('inputIv').value = document.getElementById('iv').value
});

// ---

// RSA
let privateKey, publicKey;

function generateKeys() {
    const rsa = forge.pki.rsa;
    rsa.generateKeyPair({
        bits: 2048,
        e: 0x10001
    }, function(err, keypair) {
        privateKey = keypair.privateKey;
        publicKey = keypair.publicKey;

        document.getElementById('publicKey').value = forge.pki.publicKeyToPem(publicKey);
        document.getElementById('privateKey').value = forge.pki.privateKeyToPem(privateKey);
    });
}

function encryptMessage() {
    const message = document.getElementById('message').value;
    const encrypted = publicKey.encrypt(message, 'RSA-OAEP', {
        md: forge.md.sha256.create(),
        mgf1: forge.mgf1.create()
    });
    document.getElementById('encryptedMessage').value = forge.util.encode64(encrypted);
}

function decryptMessage() {
    const encryptedMessage = forge.util.decode64(document.getElementById('encryptedMessage').value);
    const privateKeyPem = document.getElementById('privateKeyInput').value;
    try {
        const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
        const decrypted = privateKey.decrypt(encryptedMessage, 'RSA-OAEP', {
            md: forge.md.sha256.create(),
            mgf1: forge.mgf1.create()
        });
        document.getElementById('decryptedMessage').value = decrypted;
    } catch (error) {
        document.getElementById('decryptedMessage').value = "Decryption failed: " + error.message;
    }
}

function pasteKeys() {
    document.getElementById('privateKeyInput').value = document.getElementById('privateKey').value
}

// ---

// VIGENERE CIPHER
function vigenereCipher(str, key, action) {
    let output = '';
    let keyIndex = 0;
    const adjust = action === 'encrypt' ? 1 : -1;

    for (let i = 0; i < str.length; i++) {
        let char = str[i];
        if (char.match(/[a-z]/i)) {
            const keyChar = key[keyIndex % key.length];
            const keyShift = keyChar.toLowerCase().charCodeAt(0) - 'a'.charCodeAt(0);
            const code = str.charCodeAt(i);
            let base = 'A'.charCodeAt(0);

            if (char === char.toLowerCase()) {
                base = 'a'.charCodeAt(0);
            }

            char = String.fromCharCode(((code - base + (keyShift * adjust)) % 26 + 26) % 26 + base);
            keyIndex++;
        }
        output += char;
    }
    return output;
}

// Fungsi baru untuk otomatisasi Enkripsi Vigenère
function encryptVigenere() {
    const inputText = document.getElementById('vigenereInputText').value;
    const key = document.getElementById('vigenereKey').value;
    if (key) {
        const encryptedText = vigenereCipher(inputText, key, 'encrypt');
        document.getElementById('vigenereCipherText').value = encryptedText;
    } else {
        document.getElementById('vigenereCipherText').value = "";
    }
}

// Fungsi baru untuk otomatisasi Dekripsi Vigenère
function decryptVigenere() {
    const cipherText = document.getElementById('vigenereCipherText').value;
    const key = document.getElementById('vigenereDecryptKey').value;
    if (key) {
        const decryptedText = vigenereCipher(cipherText, key, 'decrypt');
        document.getElementById('vigenereResultText').value = decryptedText;
    } else {
        document.getElementById('vigenereResultText').value = "";
    }
}

// Tambahkan event listeners baru
document.getElementById('vigenereInputText').addEventListener('input', encryptVigenere);
document.getElementById('vigenereKey').addEventListener('input', encryptVigenere);
document.getElementById('vigenereCipherText').addEventListener('input', decryptVigenere);
document.getElementById('vigenereDecryptKey').addEventListener('input', decryptVigenere);

// ---

// SHA-256
async function hashText(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}

// Event Listener untuk SHA-256
document.getElementById('hashBtn').addEventListener('click', async function() {
    const inputText = document.getElementById('hashInputText').value;
    const hashedText = await hashText(inputText);
    document.getElementById('hashOutputText').value = hashedText;
});




// AES (Bagian yang diubah total)
document.getElementById('generateKeyIv').addEventListener('click', async () => {
    const keySize = parseInt(document.getElementById('keySize').value);
    const keyBytes = keySize / 8; // 128 bit = 16 byte, 256 bit = 32 byte
    const key = window.crypto.getRandomValues(new Uint8Array(keyBytes));
    const iv = window.crypto.getRandomValues(new Uint8Array(16)); // IV selalu 16 byte untuk AES

    document.getElementById('key').value = Array.from(key).map(b => b.toString(16).padStart(2, '0')).join('');
    document.getElementById('iv').value = Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('');
});

document.getElementById('encrypt').addEventListener('click', async () => {
    const plaintext = document.getElementById('plaintext').value;
    const keyHex = document.getElementById('key').value;
    const ivHex = document.getElementById('iv').value;

    if (keyHex.length === 0 || ivHex.length === 0) {
        alert("Harap buat kunci dan IV terlebih dahulu.");
        return;
    }
    
    // Periksa panjang kunci
    const keyBytes = keyHex.length / 2;
    if (keyBytes !== 16 && keyBytes !== 32) {
        alert('Panjang kunci tidak valid. Harap gunakan kunci 128-bit (16 byte) atau 256-bit (32 byte).');
        return;
    }

    const key = new Uint8Array(keyHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const iv = new Uint8Array(ivHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

    const cryptoKey = await window.crypto.subtle.importKey(
        'raw',
        key, {
            name: 'AES-CBC'
        },
        false,
        ['encrypt']
    );

    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);
    const paddedData = new Uint8Array(16 * Math.ceil(data.byteLength / 16));
    paddedData.set(data);

    try {
        const ciphertext = await window.crypto.subtle.encrypt({
                name: 'AES-CBC',
                iv
            },
            cryptoKey,
            paddedData
        );

        document.getElementById('ciphertext').value = btoa(String.fromCharCode(...new Uint8Array(ciphertext)));
    } catch (e) {
        alert("Gagal melakukan enkripsi. Pastikan kunci dan IV sudah benar.");
    }
});

document.getElementById('decrypt').addEventListener('click', async () => {
    const ciphertext = document.getElementById('ciphertext').value;
    const keyHex = document.getElementById('inputKey').value;
    const ivHex = document.getElementById('inputIv').value;

    // Validasi panjang kunci untuk dekripsi
    if (keyHex.length !== 32 && keyHex.length !== 64) {
        alert('Panjang kunci tidak valid. AES key harus 128-bit (32 karakter hex) atau 256-bit (64 karakter hex).');
        return;
    }
    
    // Validasi panjang IV
    if (ivHex.length !== 32) {
        alert('Panjang IV tidak valid. IV harus 16 byte (32 karakter hex).');
        return;
    }

    const key = new Uint8Array(keyHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const iv = new Uint8Array(ivHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const ciphertextBytes = new Uint8Array(atob(ciphertext).split('').map(c => c.charCodeAt(0)));

    try {
        const cryptoKey = await window.crypto.subtle.importKey(
            'raw',
            key, {
                name: 'AES-CBC'
            },
            false,
            ['decrypt']
        );

        const decryptedData = await window.crypto.subtle.decrypt({
                name: 'AES-CBC',
                iv
            },
            cryptoKey,
            ciphertextBytes
        );

        const decoder = new TextDecoder();
        // Hapus karakter null (padding) di akhir
        document.getElementById('decryptedtext').value = decoder.decode(decryptedData).replace(/\0/g, '');
    } catch (e) {
        alert("Dekripsi gagal. Periksa kembali kunci, IV, dan teks terenkripsi.");
    }
});

// Pastikan kode ini tidak berubah
document.getElementById('pasteKey').addEventListener('click', function() {
    document.getElementById('inputKey').value = document.getElementById('key').value
    document.getElementById('inputIv').value = document.getElementById('iv').value
});

// GENERAL TAB FUNCTIONALITY
// ... (Kode general tab functionality tidak berubah, tetap di bawah)

// GENERAL TAB FUNCTIONALITY
document.addEventListener('DOMContentLoaded', (event) => {
    const tabLinks = document.querySelectorAll('.nav-link');

    tabLinks.forEach(tab => {
        tab.addEventListener('click', () => {
            localStorage.setItem('activeTab', tab.id);
        });
    });

    const activeTabId = localStorage.getItem('activeTab');

    if (activeTabId) {
        tabLinks.forEach(tab => tab.classList.remove('active'));
        const activeTab = document.getElementById(activeTabId);
        activeTab.classList.add('active');
        const tabContentId = activeTab.getAttribute('data-bs-target');
        const tabContent = document.querySelector(tabContentId);
        const allTabContents = document.querySelectorAll('.tab-pane');

        allTabContents.forEach(content => content.classList.remove('show', 'active'));
        tabContent.classList.add('show', 'active');
    }
});