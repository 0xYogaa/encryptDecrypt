// --------------------------------------------------------
// Librairies
// --------------------------------------------------------

const keccak256 = require('keccak256')
const { ethers } = require("ethers");


// --------------------------------------------------------
// Functions
// --------------------------------------------------------

// Xor hexadecimal data
function XOR_hex(_a, _b) {
    var a = _a.replace('0x', ''),
        b = _b.replace('0x', ''),
        i = a.length,
        j = b.length,
        res = "";
    while (i-->0 && j-->0)
        res = (parseInt(a.charAt(i), 16) ^ parseInt(b.charAt(j), 16)).toString(16) + res;
    return ('0x'+res);
}

// Convert a decimal number to its UINT256 equivalent
function toUint256(_dec) {
    let bytes = hexToBytes(_dec.toString(16));
    for (var uint256 = [], i = 31; i >= 0; i--) {
        if (bytes.length <= i)
            uint256.push(0);
        else
            uint256.push(bytes[i]);
    }
    return bytesToHex(uint256);
}

// Convert an hexadecimal number to its Bytes32 equivalent
function toBytes32(_hex, _index) {
    let array = hexToBytes(_hex);
    for (var bytes32 = [], i = _index; i < _index+32; i++) {
        if (array.length <= i)
            bytes32.push(00);
        else
            bytes32.push(array[i]);
    }
    return bytesToHex(bytes32);
}

// Convert a hex string to a byte array
function hexToBytes(_hex) {
    let hex = _hex.replace('0x', '');
    for (var bytes = [], c = 0; c < hex.length; c += 2)
        bytes.push(parseInt(hex.substr(c, 2), 16));
    return bytes;
}

// Convert a byte array to a hex string
function bytesToHex(bytes) {
    for (var hex = [], i = 0; i < bytes.length; i++) {
        var current = bytes[i] < 0 ? bytes[i] + 256 : bytes[i];
        hex.push((current >>> 4).toString(16));
        hex.push((current & 0xF).toString(16));
    }
    return ('0x'+hex.join(""));
}


// --------------------------------------------------------
// Main
// --------------------------------------------------------

/**
 * Reproduce the function 'createDelayedRevealBatch' from https://github.com/thirdweb-dev/typescript-sdk/blob/main/src/core/classes/delayed-reveal.ts
 * with the help of the deployed contract https://testnet.snowtrace.io/address/0x3b71f5be914f9bcf9d785d55d4a7c9fc3670e5f8
 * @param _baseUri - base uri
 * @param _password - the password that will be used to reveal these NFTs
 */
async function delayReveal(_baseUri, _password) {

    // Logs
    console.log("\n delayReveal()");

    // Init
    const chainId           = 43113;                                                // Avax Fuji chain ID
    const baseUriId         = 1;                                                    // getBaseURICount() from https://testnet.snowtrace.io/address/0x3b71f5be914f9bcf9d785d55d4a7c9fc3670e5f8
    const batchTokenIndex   = 0;                                                    // Batch (from thirdweb)
    const contractAddress   = "0x3B71F5be914f9BCf9D785D55d4a7C9fc3670e5F8";         // Contract address (https://testnet.snowtrace.io/address/0x3b71f5be914f9bcf9d785d55d4a7c9fc3670e5f8)

    // Hash password
    const hashedPassword = await ethers.utils.solidityKeccak256(
      ["string", "uint256", "uint256", "address"],
      [_password, chainId, batchTokenIndex, contractAddress],
    );

    // Get variables
    const data = ethers.utils.hexlify(ethers.utils.toUtf8Bytes(_baseUri));
    const key = hashedPassword;

    // Logs (use this result to test encryptDecrypt(data, key) function on https://testnet.snowtrace.io/address/0x3b71f5be914f9bcf9d785d55d4a7c9fc3670e5f8)
    console.log("data:", data);
    console.log("key:", key);

    // Encrypt/Decrypt
    const encryptedData = encryptDecrypt(data, key);

    // Logs
    console.log("Result encrypted", encryptedData);

    // Encrypt/Decrypt
    const decryptedData = encryptDecrypt(encryptedData, key);

    // Logs
    console.log("Result decrypted", ethers.utils.toUtf8String(decryptedData));
}

/**
 * Reproduce the function 'encryptDecrypt' from https://github.com/thirdweb-dev/contracts/blob/main/contracts/drop/DropERC721.sol
 * @param _data - base uri encrypted
 * @param _key - hashed password
 * 
 * You can test this function officialy on Avax Fuji testnet (deploy with thirdweb)
 * https://testnet.snowtrace.io/address/0x3b71f5be914f9bcf9d785d55d4a7c9fc3670e5f8
 * encryptDecrypt(data, key)
 * Exemple
 * data = 0x697066733a2f2f516d63316772346935566d573935664c44414c3862385845384b3865677679446f784e55504853386f42324c66642f
 * key  = 0x1eb48b4095d7fe2fd7ca717f2c8f66c3cf99ff800399f5d8eb0c04aceaa7208c
 * result = 0xc71d5317d22ab6b49089120b35f6f11ff6c462a2a6a1d791eb0847ce6e72f63d8b131236a0f78afb431a20e0988605cb0e3dc5e979d7
 */
function encryptDecrypt( _data, _key) {

    // Logs
    console.log("\n encryptDecrypt()");

    // Store data length on stack for later use
    let dataLength = hexToBytes(_data).length;

    // Result
    let result = [];

    // Iterate over the data stepping by 32 bytes
    for (let i = 0; i < dataLength; i += 32) {

        // Generate hash of the key and offset without web3
        let uint256 = toUint256(i).replace('0x','');
        let hash = keccak256([_key, uint256].join('')).toString('hex')

        // Read chunk
        let chunk = toBytes32(_data, i);

        // XOR chunk with hash
        chunk = XOR_hex(chunk, hash);
        
        // Save result
        result.push(chunk.replace('0x', ''));
    }

    // Return result
    return '0x'+result.join('').substring(0, dataLength*2);
}


// Execute
delayReveal("ipfs://Qmc1gr4i5VmW95gdhjExampleDeCID/", "testPassword20");
