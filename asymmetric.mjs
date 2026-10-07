// 9/23/26 
// See notes on ipad for how this plays out

// ECDSA - Digital Signatures

 
import { bls12_381 } from "@noble/curves/bls12-381.js";
import { ed25519 } from "@noble/curves/ed25519.js";

export function demoSignature(message) {
    const privateKey = ed25519.utils.randomSecretKey()
    const publicKey = ed25519.getPublicKey(privateKey)

    // encodedMessage = original message
    const encodedMessage = new TextEncoder().encode(message)

    const signature = ed25519.sign(encodedMessage, privateKey) // Alice signing from notes

    console.log("Signature: ", signature.toString())

    const checked = ed25519.verify(signature, encodedMessage, publicKey)

    console.log("Signature checked? ", checked)
}

// 10/7/26
// BLS Signatures and Pairings
export function demoBlsSignatures(message) {
    // get hash of message, and then multiply by private key
    // bls12_381 --> gets us a different curve

    ///////////
    // ALICE //
    //////////

    // x
    const privateKey = bls12_381.utils.randomSecretKey()
    // cG
    const publicKey = bls12_381.longSignatures.getPublicKey(privateKey) // need the longSignatures
    // m
    const encodedMessage = new TextEncoder().encode(message)
    // H(m), point in G2
    const hashedMessage = bls12_381.longSignatures.hash(encodedMessage)
    // x H(m)
    const signature = bls12_381.longSignatures.sign(hashedMessage, privateKey)
    console.log("Signatures: ", signature.toString())

    /////////
    // BOB //
    /////////
   
    // m
    const encodedMessage_p = new TextEncoder().encode(message)
    // H(m)'
    const hashedMessage_p = bls12_381.longSignatures.hash(encodedMessage_p)
    // is e(G, signature) == e(publicKey, encodedMessage_p (prime))
    const verified = bls12_381.longSignatures.verify(signature, hashedMessage_p, publicKey)
    console.log("Signature verified? ", verified)
}

export function demoAggragateSignatures(message) {
    const privateKeys = [ 

    ]

    const publicKeys = [

    ]

    // aggregatePublicKey
    const clasPublicKey = 

    // Sign a message: each participant signs individually
}

export function verifyAggregate() {
    
}
