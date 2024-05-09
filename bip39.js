const crypto = require('crypto');
const fs = require('fs');
const readline = require('readline');

// Constants
const BITS = 256;
const CHECKSUM_BITS = BITS / 32;
const BYTE_SIZE = BITS / 8;

// Read BIP39 wordlist from file
function getBip39WordList() {
    return new Promise((resolve, reject) => {
        fs.readFile('english.txt', 'utf8', (err, data) => {
            if (err) reject(err);
            else resolve(data.split('\n'));
        });
    });
}

// Generate random seed
function generateSeed(length = BYTE_SIZE) {
    return crypto.randomBytes(length);
}

// Calculate checksum
function calculateChecksum(seed, bits) {
    const hash = crypto.createHash('sha256').update(seed).digest('hex');
    const hashBinary = hash.match(/.{1,2}/g)
        .map(byte => parseInt(byte, 16).toString(2).padStart(8, '0'))
        .join('')
        .slice(0, bits);
    return hashBinary;
}

// Convert seed to binary with checksum
function seedToBinaryWithChecksum(seed) {
    const binary = seed.toString('hex')
        .match(/.{1,2}/g)
        .map(byte => parseInt(byte, 16).toString(2).padStart(8, '0'))
        .join('');
    const checksum = calculateChecksum(seed, CHECKSUM_BITS);
    const binaryWithChecksum = binary + checksum;
    console.log("\n\nSeed Binary With Checksum: ", binaryWithChecksum);
    return binaryWithChecksum;
}

// Split binary into 11-bit chunks
function splitIntoLots(binary) {
    const lots = [];
    for (let i = 0; i < binary.length; i += 11) {
        lots.push(binary.slice(i, i + 11));
    }
    return lots;
}

// Convert binary to wordlist indices
function binaryToIndices(lots) {
    return lots.map(lot => parseInt(lot, 2));
}

// Get mnemonic words from indices
function indicesToWords(indices, wordList) {
    return indices.map(index => wordList[index]);
}

// Convert mnemonic to binary seed using PBKDF2 with passphrase support
function mnemonicToSeed(mnemonic, passphrase = '') {
    // Normalize mnemonic sentence and passphrase using UTF-8 NFKD
    const normalizedMnemonic = Buffer.from(mnemonic.normalize('NFKD'), 'utf8');
    const salt = Buffer.from('mnemonic' + passphrase.normalize('NFKD'), 'utf8');
    // Use PBKDF2 to derive a 512-bit (64 bytes) key using the HMAC-SHA512 PRF
    // The iteration count is set to 2048 as specified
    const seed = crypto.pbkdf2Sync(normalizedMnemonic, salt, 2048, 64, 'sha512');
    console.log('\n\nImported Seed in Hex:', seed.toString('hex'));
    return seed;
}


// Interactive CLI
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

function main() {
    getBip39WordList().then(bip39WordList => {
        rl.question('\n\nGenerate new mnemonic (y/n)?: ', answer => {
            if (answer.toLowerCase() === 'y') {
                const seed = generateSeed();
                const binaryWithChecksum = seedToBinaryWithChecksum(seed);
                const lots = splitIntoLots(binaryWithChecksum);
                const indices = binaryToIndices(lots);
                const words = indicesToWords(indices, bip39WordList);
                console.log('\n\nGenerated Mnemonic:', words.join(' '));

                rl.close();
            } else {
                rl.question('\n\nEnter your mnemonic seed: ', mnemonic => {
                    const seed = mnemonicToSeed(mnemonic);
                    rl.close();
                });
            }
        });
    }).catch(error => {
        console.error('\n\nError reading the BIP39 wordlist:', error);
        rl.close();
    });
}

main();
