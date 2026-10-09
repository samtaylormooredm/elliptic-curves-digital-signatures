// 9/23/26 
// See notes on ipad for how this plays out

// ECDSA - Digital Signatures

 
import { bls } from "@noble/curves/abstract/bls";
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
    // Sign a message: each participant signs individually
    // Aggergate signature: sum the signatures (use the library)

    // We have 3 Alices in this example
    const NUM_PPL = 3

    // Private/public key generation is done individually, per student (not aggregate)
    const privateKeys = []

    for (let i = 0; i < NUM_PPL; i++) {
        privateKeys.push(
            bls12_381.utils.randomSecretKey()
        )
    }

    // mapping instead of using for loop, get each member of the private keys
    //   and map them to their public key
    const publicKeys = privateKeys.map(
        (k) => bls12_381.longSignatures.getPublicKey(k)
    )

    // Each person signs the message
    const encodedMessage = new TextEncoder().encode(message)
    const hashedMessage = bls12_381.longSignatures.hash(encodedMessage)

    // Generate signatures based on their private keys
    const signatures = privateKeys.map(
        (k) => bls12_381.longSignatures.sign(hashedMessage, privateKey)
    )

    // Aggregate our signatures without sharing anything about the private keys
    const classSignature = bls12_381.longSignatures.aggregateSignatures(signatures)
    const clasPublicKey = bls12_381.longSignatures.aggregatePublicKeys(publicKeys)

    // Verification
    // is e(G, signature) == e(publicKey, encodedMessage_p (prime))
    const verified = bls12_381.longSignatures.verify(classSignature, hashedMessage, classPublicKey)

}

export function verifyAggregate() {
    

}
