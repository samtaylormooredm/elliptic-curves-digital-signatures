// 9/30/26
import { ed25519 } from '@noble/curves/ed25519.js'

import * as polynomials from './polynomials.mjs'

import { randomBytes } from '@noble/hashes/utils.js'
import { bytesToNumberBE } from '@noble/curves/utils.js'

const defaultField  = ed25519.Point.Fn

// Polynomial: [a0, a1, ..., ad] represents P(x) = a0 + a1*x + ... + ad*x^d
// a0 is the secret
// evaluate(coefficients, x, field) returns P(x) (modular arithmetic in the field)
//
// Share format: { number: x, subSecret: P(x) } (Javascript BigInt)
// Share numbers use x = 1n, 2n, 3n, ...; the position x = 0 is reserved for the secret
//
// lagrange(xs, ys, field) receives corresponding x- and y-coordinate arrays
// Example: lagrange([1n, 2n], [P(1n), P(2n)], field)
// It returns [a0, a1, ..., ad], using the same polynomial coefficient format
// The reconstructed secret is P(0) = a0.

export function getRandomElement(field) {
	while(true) {
		const value = bytesToNumberBE(randomBytes(field.BYTES))

		if(value < field.ORDER) {
			return value
		}
	}
}

export function generateShares(secret, numberThreshold, numberShares, field = defaultField) {
}

export function reconstructSecret(shares, field = defaultField) {
}