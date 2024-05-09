const crypto = require('crypto');
const secp256k1 = require('secp256k1');

// Generate HMAC-SHA512 hash
function hmacSHA512(key, data) {
    return crypto.createHmac('sha512', key).update(data).digest();
}

// Master key generation
function generateMasterKey(seed) {
    const I = hmacSHA512('Bitcoin seed', seed);
    const IL = I.slice(0, 32);
    const IR = I.slice(32);
    return { masterPrivateKey: IL, chainCode: IR };
}

// Derive the public key from a private key
function derivePublicKey(privateKey) {
    return secp256k1.publicKeyCreate(privateKey, true);
}

// Generalized child key derivation at multiple levels
function deriveChildKey(parentKey, parentChainCode, indices) {
    let currentNode = { privateKey: parentKey, chainCode: parentChainCode };
    indices.forEach(index => {
        const hardened = index >= 0x80000000;
        let data;
        if (hardened) {
            data = Buffer.concat([Buffer.from([0]), currentNode.privateKey, Buffer.from(indexBuffer(index))]);
        } else {
            const parentPublicKey = secp256k1.publicKeyCreate(currentNode.privateKey, true);
            data = Buffer.concat([parentPublicKey, Buffer.from(indexBuffer(index))]);
        }
        const I = hmacSHA512(currentNode.chainCode, data);
        const IL = I.slice(0, 32);
        const IR = I.slice(32);
        currentNode.privateKey = secp256k1.privateKeyTweakAdd(currentNode.privateKey, IL);
        currentNode.chainCode = IR;
    });
    return { childPrivateKey: currentNode.privateKey, chainCode: currentNode.chainCode };
}

// Helper function to convert index to buffer
function indexBuffer(index) {
    const buffer = Buffer.alloc(4);
    buffer.writeUInt32BE(index, 0);
    return buffer;
}

// Example usage
// const seed = crypto.randomBytes(64); // Or import from BIP39 mnemonic
const seed = "6bf1276fcfad14c61f486943423f327a7343bce96cda8961d4d8587e5268ec8b2900d8c842e6df011d5556d4437ab3a4775e5b34c7d1c33e8735deb79eab364f"; 
const { masterPrivateKey, chainCode } = generateMasterKey(seed);
console.log('Master Private Key:', masterPrivateKey.toString('hex'));
console.log('Master Chain Code:', chainCode.toString('hex'));

// Generate child key at index N
let indexN = 1; // Non-hardened example
const childAtN = deriveChildKey(masterPrivateKey, chainCode, [indexN]);
console.log(`Child Key at index ${indexN} :`, childAtN.childPrivateKey.toString('hex'));

// Generate child key at index N at derivation level M
const indexNAtM = [1, 0x80000003]; // First level non-hardened, second level hardened
const childAtNAtM = deriveChildKey(masterPrivateKey, chainCode, indexNAtM);
console.log(`Child Key at index ${indexNAtM[0]} at derivation ${indexNAtM[1]-0x80000000}:`, childAtNAtM.childPrivateKey.toString('hex'));
