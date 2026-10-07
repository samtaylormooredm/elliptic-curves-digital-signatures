// Documentation in https://nodejs.org/api/crypto.htm
// ST: To run, in terminal: node index.mjs

import * as crypto from 'crypto'
import { encrypt, encrypt2, decrypt, decrypt2 } from './symmetric.mjs'
import { sha256 } from '@noble/hashes/sha2.js';
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { initializeVRF, generate, verify } from './vrf.mjs'
import { DiffieHellman } from 'crypto';
import { demoDiffieHellman } from './diffie-hellman.mjs';
// import { ed25519 } from '@noble/curves/ed25519.js'
import { demoBlsSignatures, demoSignature } from './asymmetric.mjs';
import * as polynomials from './polynomials.mjs'
import {
    calculateHash,
    timestamp,
    verify as verifyTimestamp
} from './timestamp.mjs'
import {generateShares, reconstructSecret} from './secret-sharing.mjs'


// Generates random bytes
function testRandom() {
    // ST: 32 bytes = 256 bits
    // When displayed in hex, each byte is represented by 2 hex characters,
    // so 32 random bytes are shown as 64 hex characters.

    let random = crypto.randomBytes(32)

    console.log("Random numbers:", random.toString('hex'))
}


// Hashes
function testHashing() {
    let message = "I'm going to the Taylor Swift show"

    const hasher = crypto.createHash('sha256')
        .update(message)
        .digest()

    const hashed = hasher.toString('hex')

    console.log("Hashed message:", hashed)
}


// Symmetric encryption
function testSymmetric() {
    let key = "TaylorSwift"

    let encrypted = encrypt(key, "And I'm going to buy a T-shirt")
    console.log("Encrypted message:", encrypted)

    let decrypted = decrypt(key, encrypted)
    console.log("Decrypted message:", decrypted)
}

function testSymmetric2() {
    let key = "TaylorSwift"

    let encrypted = encrypt2(key, "And I'm going to buy a T-shirt")
    console.log("Encrypted message:", encrypted)

    let decrypted = decrypt2(key, encrypted)
    console.log("Decrypted message:", decrypted)
}

function testSymmetricAuthenticated() {
    let key = "TaylorSwift"

    let encrypted = encrypt2(key, "And I'm going to buy a T-shirt")
    console.log("Encrypted message:", encrypted)

    let decrypted = decrypt2(key, encrypted)
    console.log("Decrypted message:", decrypted)
}


// Verifiable Random Function
function testVRF() {
    const vrf = initializeVRF()
    const i = 1
    const result = generate(i)

    console.log("VRF setup:", vrf)
    console.log("Proof:", result.pi)
    console.log("Random number:", result.ri)

    console.log("Verified:", verify(result.ri, result.pi, i))
    console.log("Verified with wrong i:", verify(result.ri, result.pi, 2))
}

function testTimestamp() {
    const hash = calculateHash('test.txt')
    const result = timestamp(hash)

    console.log("Timestamp:", result)
    console.log("Timestamp verified:", verifyTimestamp(hash, result))

    const wrongHash = crypto.createHash('sha256')
        .update("different contents")
        .digest()

    console.log(
        "Timestamp verified with wrong hash:",
        verifyTimestamp(wrongHash, result)
    )
}

// Shamir's Secret Sharing
// 10/2/26
function testSecretSharing() {
    const coefficients = [10n, 100n, 1000n]; // ST note: have to do n at end of each literal for JS
    const eval42  = polynomials.evaluate(coefficients, 42n, ed25519.Point.Fn);
    const eval47  = polynomials.evaluate(coefficients, 47n, ed25519.Point.Fn);
    const eval49  = polynomials.evaluate(coefficients, 49n, ed25519.Point.Fn);

    const coefficients_prime = polynomials.lagrange([42n, 47n, 49n], [eval42, eval47, eval49], ed25519.Point.Fn)
    console.log(coefficients);
    console.log(coefficients_prime);

    let secret = 1989n

    let shares = generateShares(secret, 3, 5)
    console.log("shares = ", shares)

    let secretRecovered = reconstructSecret([shares[1], shares[3], shares[4]])

    console.log("Shamir secret sharing recovered: ", secret == secretRecovered)
}



// Run tests

// console.log("\n--- Test: Random Bytes ---")
// testRandom()
// console.log("\n--- Test: Hashing ---")
// testHashing()
// console.log("\n--- Test: Symmetric Encryption ---")
// testSymmetric()
// console.log("\n--- Test: Symmetric Encryption 2 ---")
// testSymmetric2()
// console.log("\n--- Test: Authenticated Symmetric Encryption ---")
// testSymmetricAuthenticated()
// console.log("\n--- Test: Verifiable Random Function ---")
// testVRF()
// // console.log("\n--- Test: Timestamp Hash ---")
// // testTimestamp()

// // Tests from class
// console.log("\n--- Test: Diffie Hellman ---")
// demoDiffieHellman()
// console.log("\n--- Test: Asymmetric cryptography [[x]signature, encryption] ---")
// demoSignature("Sign this!")
// testVRF()
// testTimestamp()

// // Test shamir secret sharing
// console.log("\n--- Test: Shamir Secret Sharing ---")
// testSecretSharing()

// Test BLS Signatures
demoBlsSignatures("Hey Bob, have $100 (nonce 17)")