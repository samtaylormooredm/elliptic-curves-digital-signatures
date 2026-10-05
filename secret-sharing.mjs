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
	// numberThreshold = how many ppl that are needed to open the vault
	// numberShares = num of people we have
	let coefficients = [secret]

	// Building the random coefficients of the polynomial
	for (let i = 0; i < numberThreshold - 1; i++) {
		coefficients.push(getRandomElement(field))
	}

	// Evaluate that polynomial at x = 1n, 2n, 3n, ... to create each person's share
	let shares = []

	// ST: Have to start at 1 so no one gets the secret
	for (let i = 1; i <= numberShares; i++) {
		shares.push({
			number: BigInt(i),
			subSecret: polynomials.evaluate(coefficients, BigInt(i), field)
		})
	}
	return shares
	
}

export function reconstructSecret(shares, field = defaultField) {
	let xs = []
	let ys = []

	for (const x of shares) {
		xs.push(x.number)
		ys.push(x.subSecret)
	}
	
	const reconstructed_coefficients = polynomials.lagrange(xs, ys, field)
	return polynomials.evaluate(reconstructed_coefficients, 0n, defaultField)
}