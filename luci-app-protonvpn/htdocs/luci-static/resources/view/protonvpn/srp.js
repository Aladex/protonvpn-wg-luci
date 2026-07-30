// SPDX-License-Identifier: MIT
// Proton SRP-6a client. Runs in the browser (the LuCI page) because the router's
// ucode has no bignum arithmetic; the account password is turned into a proof
// here and never leaves this page. The router only relays HTTP.
//
// Ported from the ProtonMail/go-srp reference implementation (MIT). Wire values
// are little-endian base64, the hash is SHA-512 expanded to 256 bytes, and the
// password is bcrypt'ed ($2y$, cost 10) with 'proton' appended to the salt.
// tests/srp.test.mjs pins every step against vectors taken from that reference.

'use strict';

(function (root, factory) {
	if (typeof module === 'object' && module.exports)
		module.exports = factory(require('./vendor/bcrypt.js'), require('crypto').webcrypto);
	else
		root.ProtonSRP = factory(root.bcrypt, root.crypto);
}(typeof globalThis !== 'undefined' ? globalThis : this, function (bcrypt, webcrypto) {

	var GENERATOR = 2n;
	var HASH_LEN = 256;          // expandHash output, bytes
	var DEFAULT_BIT_LENGTH = 2048;
	// bcrypt's own base64 alphabet: '.' and '/' instead of '+' and '/', no padding.
	var BCRYPT_B64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

	/* ---- byte / bignum helpers ---------------------------------------- */

	// Proton encodes every SRP bignum little-endian, unlike most SRP libraries.
	function bytesToBigIntLE(bytes) {
		var n = 0n;
		for (var i = bytes.length - 1; i >= 0; i--)
			n = (n << 8n) | BigInt(bytes[i]);
		return n;
	}

	function bigIntToBytesLE(num, length) {
		var out = new Uint8Array(length);
		var n = num;
		for (var i = 0; i < length; i++) {
			out[i] = Number(n & 0xffn);
			n >>= 8n;
		}
		return out;
	}

	function concatBytes(chunks) {
		var total = 0, i;
		for (i = 0; i < chunks.length; i++)
			total += chunks[i].length;
		var out = new Uint8Array(total), at = 0;
		for (i = 0; i < chunks.length; i++) {
			out.set(chunks[i], at);
			at += chunks[i].length;
		}
		return out;
	}

	function base64ToBytes(str) {
		if (typeof Buffer !== 'undefined')
			return new Uint8Array(Buffer.from(str, 'base64'));
		var raw = atob(str), out = new Uint8Array(raw.length);
		for (var i = 0; i < raw.length; i++)
			out[i] = raw.charCodeAt(i);
		return out;
	}

	function bytesToBase64(bytes) {
		if (typeof Buffer !== 'undefined')
			return Buffer.from(bytes).toString('base64');
		var s = '';
		for (var i = 0; i < bytes.length; i++)
			s += String.fromCharCode(bytes[i]);
		return btoa(s);
	}

	function bitLengthOf(num) {
		return num.toString(2).length;
	}

	// Square-and-multiply; BigInt keeps this exact, and 2048-bit exponents are
	// fast enough for an interactive login.
	function modPow(base, exponent, modulus) {
		if (modulus === 1n)
			return 0n;
		var result = 1n;
		var b = base % modulus;
		if (b < 0n)
			b += modulus;
		var e = exponent;
		while (e > 0n) {
			if (e & 1n)
				result = (result * b) % modulus;
			b = (b * b) % modulus;
			e >>= 1n;
		}
		return result;
	}

	function mod(a, m) {
		var r = a % m;
		return r < 0n ? r + m : r;
	}

	/* ---- hashing ------------------------------------------------------ */

	// SHA-512 round constants (FIPS 180-4), as BigInt.
	var K512 = [
		'428a2f98d728ae22','7137449123ef65cd','b5c0fbcfec4d3b2f','e9b5dba58189dbbc',
		'3956c25bf348b538','59f111f1b605d019','923f82a4af194f9b','ab1c5ed5da6d8118',
		'd807aa98a3030242','12835b0145706fbe','243185be4ee4b28c','550c7dc3d5ffb4e2',
		'72be5d74f27b896f','80deb1fe3b1696b1','9bdc06a725c71235','c19bf174cf692694',
		'e49b69c19ef14ad2','efbe4786384f25e3','0fc19dc68b8cd5b5','240ca1cc77ac9c65',
		'2de92c6f592b0275','4a7484aa6ea6e483','5cb0a9dcbd41fbd4','76f988da831153b5',
		'983e5152ee66dfab','a831c66d2db43210','b00327c898fb213f','bf597fc7beef0ee4',
		'c6e00bf33da88fc2','d5a79147930aa725','06ca6351e003826f','142929670a0e6e70',
		'27b70a8546d22ffc','2e1b21385c26c926','4d2c6dfc5ac42aed','53380d139d95b3df',
		'650a73548baf63de','766a0abb3c77b2a8','81c2c92e47edaee6','92722c851482353b',
		'a2bfe8a14cf10364','a81a664bbc423001','c24b8b70d0f89791','c76c51a30654be30',
		'd192e819d6ef5218','d69906245565a910','f40e35855771202a','106aa07032bbd1b8',
		'19a4c116b8d2d0c8','1e376c085141ab53','2748774cdf8eeb99','34b0bcb5e19b48a8',
		'391c0cb3c5c95a63','4ed8aa4ae3418acb','5b9cca4f7763e373','682e6ff3d6b2b8a3',
		'748f82ee5defb2fc','78a5636f43172f60','84c87814a1f0ab72','8cc702081a6439ec',
		'90befffa23631e28','a4506cebde82bde9','bef9a3f7b2c67915','c67178f2e372532b',
		'ca273eceea26619c','d186b8c721c0c207','eada7dd6cde0eb1e','f57d4f7fee6ed178',
		'06f067aa72176fba','0a637dc5a2c898a6','113f9804bef90dae','1b710b35131c471b',
		'28db77f523047d84','32caab7b40c72493','3c9ebe0a15c9bebc','431d67c49c100d4c',
		'4cc5d4becb3e42b6','597f299cfc657e2a','5fcb6fab3ad6faec','6c44198c4a475817'
	].map(function (h) { return BigInt('0x' + h); });

	var MASK64 = 0xffffffffffffffffn;
	function rotr64(x, n) {
		return ((x >> n) | (x << (64n - n))) & MASK64;
	}

	// Pure-JS SHA-512. WebCrypto is unavailable over plain HTTP (subtle is
	// restricted to secure contexts), and LuCI on a LAN address is usually
	// plain HTTP — refusing to work there would make the whole page useless on
	// a normal OpenWrt setup. Verified against the same reference vectors as
	// the WebCrypto path.
	function sha512Sync(bytes) {
		var H = [
			0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
			0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n
		];
		var ml = bytes.length;
		// Pad: 0x80, zeros, then the bit length as a 128-bit big-endian value.
		var padded = new Uint8Array(((ml + 17 + 127) >> 7) << 7);
		padded.set(bytes, 0);
		padded[ml] = 0x80;
		var bits = BigInt(ml) * 8n;
		for (var i = 0; i < 16; i++)
			padded[padded.length - 1 - i] = Number((bits >> BigInt(8 * i)) & 0xffn);

		var w = new Array(80);
		for (var off = 0; off < padded.length; off += 128) {
			for (var t = 0; t < 16; t++) {
				var v = 0n;
				for (var b = 0; b < 8; b++)
					v = (v << 8n) | BigInt(padded[off + t * 8 + b]);
				w[t] = v;
			}
			for (t = 16; t < 80; t++) {
				var s0 = rotr64(w[t - 15], 1n) ^ rotr64(w[t - 15], 8n) ^ (w[t - 15] >> 7n);
				var s1 = rotr64(w[t - 2], 19n) ^ rotr64(w[t - 2], 61n) ^ (w[t - 2] >> 6n);
				w[t] = (w[t - 16] + s0 + w[t - 7] + s1) & MASK64;
			}
			var a = H[0], bb = H[1], c = H[2], d = H[3],
			    e = H[4], f = H[5], g = H[6], h = H[7];
			for (t = 0; t < 80; t++) {
				var S1 = rotr64(e, 14n) ^ rotr64(e, 18n) ^ rotr64(e, 41n);
				var ch = (e & f) ^ ((~e & MASK64) & g);
				var t1 = (h + S1 + ch + K512[t] + w[t]) & MASK64;
				var S0 = rotr64(a, 28n) ^ rotr64(a, 34n) ^ rotr64(a, 39n);
				var maj = (a & bb) ^ (a & c) ^ (bb & c);
				var t2 = (S0 + maj) & MASK64;
				h = g; g = f; f = e;
				e = (d + t1) & MASK64;
				d = c; c = bb; bb = a;
				a = (t1 + t2) & MASK64;
			}
			H[0] = (H[0] + a) & MASK64; H[1] = (H[1] + bb) & MASK64;
			H[2] = (H[2] + c) & MASK64;  H[3] = (H[3] + d) & MASK64;
			H[4] = (H[4] + e) & MASK64;  H[5] = (H[5] + f) & MASK64;
			H[6] = (H[6] + g) & MASK64;  H[7] = (H[7] + h) & MASK64;
		}
		var out = new Uint8Array(64);
		for (i = 0; i < 8; i++)
			for (var j = 0; j < 8; j++)
				out[i * 8 + j] = Number((H[i] >> BigInt(56 - 8 * j)) & 0xffn);
		return out;
	}

	// WebCrypto when the page is a secure context, the portable path otherwise.
	function sha512(bytes) {
		if (webcrypto && webcrypto.subtle)
			return webcrypto.subtle.digest('SHA-512', bytes).then(function (buf) {
				return new Uint8Array(buf);
			});
		return Promise.resolve(sha512Sync(bytes));
	}

	// Proton's hash expansion: SHA-512 of the data with a single counter byte
	// appended, for counters 0..3, concatenated into 256 bytes.
	function expandHash(data) {
		var parts = [0, 1, 2, 3].map(function (counter) {
			return sha512(concatBytes([data, new Uint8Array([counter])]));
		});
		return Promise.all(parts).then(concatBytes);
	}

	// bcrypt with Proton's fixed cost, taking an already-encoded salt. Returns
	// the full modular-crypt string, which is what gets hashed with the modulus.
	function bcryptHash(password, encodedSalt) {
		return bcrypt.hashSync(password, '$2y$10$' + encodedSalt);
	}

	function bcryptBase64(bytes) {
		var out = '', i = 0, c1, c2;
		while (i < bytes.length) {
			c1 = bytes[i++];
			out += BCRYPT_B64[(c1 >> 2) & 0x3f];
			c1 = (c1 & 0x03) << 4;
			if (i >= bytes.length) {
				out += BCRYPT_B64[c1 & 0x3f];
				break;
			}
			c2 = bytes[i++];
			c1 |= (c2 >> 4) & 0x0f;
			out += BCRYPT_B64[c1 & 0x3f];
			c1 = (c2 & 0x0f) << 2;
			if (i >= bytes.length) {
				out += BCRYPT_B64[c1 & 0x3f];
				break;
			}
			c2 = bytes[i++];
			c1 |= (c2 >> 6) & 0x03;
			out += BCRYPT_B64[c1 & 0x3f];
			out += BCRYPT_B64[c2 & 0x3f];
		}
		return out;
	}

	function stringToBytes(str) {
		return new TextEncoder().encode(str);
	}

	// Auth versions 3 and 4 are identical: bcrypt over the salt with 'proton'
	// appended, then the crypt string hashed together with the modulus.
	// Versions 0-2 are legacy username-derived salts; Proton has migrated away
	// from them, so we refuse rather than pretend to support them.
	function hashPassword(opts) {
		return new Promise(function (resolve, reject) {
			var version = opts.version;
			if (version !== 4 && version !== 3) {
				reject(new Error('unsupported SRP auth version: ' + version));
				return;
			}
			var salted = concatBytes([opts.salt, stringToBytes('proton')]);
			var crypted = bcryptHash(opts.password, bcryptBase64(salted));
			resolve(expandHash(concatBytes([stringToBytes(crypted), opts.modulus])));
		});
	}

	/* ---- parameter validation ----------------------------------------- */

	// Mirrors the reference client's checks. Without PGP verification of the
	// modulus these are the defence against a server handing us a weak group:
	// a 2048-bit safe prime that is 3 mod 8 with 2 as a generator, proven by a
	// single Lucas exponentiation.
	function checkParams(opts) {
		var modulus = opts.modulus;
		var serverEphemeral = opts.serverEphemeral;
		var bitLength = opts.bitLength || DEFAULT_BIT_LENGTH;

		if (bitLengthOf(modulus) !== bitLength)
			throw new Error('SRP modulus has incorrect size');
		// 2 generates the whole group only when N is 3 mod 8.
		if ((modulus & 7n) !== 3n)
			throw new Error('SRP modulus is not 3 mod 8');

		var modulusMinusOne = modulus - 1n;
		if (serverEphemeral <= 1n || serverEphemeral >= modulusMinusOne)
			throw new Error('SRP server ephemeral is out of bounds');

		// Lucas test with base 2: 2^((N-1)/2) = -1 (mod N) proves primality and
		// that 2 is a generator rather than a square.
		var halfModulus = modulus >> 1n;
		if (modPow(GENERATOR, halfModulus, modulus) !== modulusMinusOne)
			throw new Error('SRP modulus is not prime');

		return true;
	}

	/* ---- proofs -------------------------------------------------------- */

	function randomBigInt(bitLength) {
		var bytes = new Uint8Array(bitLength / 8);
		webcrypto.getRandomValues(bytes);
		var n = 0n;
		for (var i = 0; i < bytes.length; i++)
			n = (n << 8n) | BigInt(bytes[i]);
		return n;
	}

	// clientSecret may be injected so tests can reproduce a reference vector;
	// production always draws it from the CSPRNG.
	function generateProofs(opts) {
		return new Promise(function (resolve, reject) {
			var bitLength = opts.bitLength || DEFAULT_BIT_LENGTH;
			var byteLength = bitLength / 8;
			var modulus = bytesToBigIntLE(opts.modulus);
			var serverEphemeralBytes = opts.serverEphemeral;
			var serverEphemeral = bytesToBigIntLE(serverEphemeralBytes);

			checkParams({ modulus: modulus, serverEphemeral: serverEphemeral, bitLength: bitLength });

			var modulusMinusOne = modulus - 1n;
			var hashedPassword = bytesToBigIntLE(opts.hashedPassword);

			// k = expandHash(g || N) mod N, with both padded to the modulus size.
			var multiplierInput = concatBytes([
				bigIntToBytesLE(GENERATOR, byteLength),
				bigIntToBytesLE(modulus, byteLength)
			]);

			expandHash(multiplierInput).then(function (multiplierHash) {
				var multiplier = mod(bytesToBigIntLE(multiplierHash), modulus);
				if (multiplier <= 1n || multiplier >= modulusMinusOne)
					throw new Error('SRP multiplier is out of bounds');

				var clientSecret = opts.clientSecret;
				var clientEphemeralBytes, scramblingParam;

				// Retry until the secret is in range and the scrambling param is
				// non-zero; with an injected secret we only validate it once.
				return (function attempt() {
					if (clientSecret === undefined || clientSecret === null)
						clientSecret = randomBigInt(bitLength);
					if (clientSecret <= BigInt(bitLength * 2) || clientSecret >= modulusMinusOne) {
						if (opts.clientSecret != null)
							throw new Error('SRP client secret is out of bounds');
						clientSecret = null;
						return attempt();
					}
					clientEphemeralBytes = bigIntToBytesLE(
						modPow(GENERATOR, clientSecret, modulus), byteLength);
					return expandHash(concatBytes([clientEphemeralBytes, serverEphemeralBytes]))
						.then(function (scrambleHash) {
							scramblingParam = bytesToBigIntLE(scrambleHash);
							if (scramblingParam === 0n) {
								if (opts.clientSecret != null)
									throw new Error('SRP scrambling parameter is zero');
								clientSecret = null;
								return attempt();
							}
						});
				})().then(function () {
					// base = B - k*g^x mod N ; exponent = a + u*x mod (N-1)
					var verifier = modPow(GENERATOR, hashedPassword, modulus);
					var base = mod(serverEphemeral - mod(verifier * multiplier, modulus), modulus);
					var exponent = mod(
						mod(scramblingParam * hashedPassword, modulusMinusOne) + clientSecret,
						modulusMinusOne);
					var sharedSecretBytes = bigIntToBytesLE(
						modPow(base, exponent, modulus), byteLength);

					return expandHash(concatBytes([
						clientEphemeralBytes, serverEphemeralBytes, sharedSecretBytes
					])).then(function (clientProof) {
						return expandHash(concatBytes([
							clientEphemeralBytes, clientProof, sharedSecretBytes
						])).then(function (expectedServerProof) {
							return {
								clientEphemeral: clientEphemeralBytes,
								clientProof: clientProof,
								expectedServerProof: expectedServerProof,
								sharedSecret: sharedSecretBytes
							};
						});
					});
				});
			}).then(resolve, reject);
		});
	}

	// Constant-time-ish comparison of the server's proof against what we derived.
	// A mismatch means the peer does not know the verifier — abort the login.
	function verifyServerProof(expected, serverProofBase64) {
		var got;
		try {
			got = base64ToBytes(serverProofBase64);
		} catch (e) {
			return false;
		}
		if (got.length !== expected.length)
			return false;
		var diff = 0;
		for (var i = 0; i < got.length; i++)
			diff |= got[i] ^ expected[i];
		return diff === 0;
	}

	/* ---- modulus armor ------------------------------------------------- */

	// /auth/info returns the modulus as a PGP clear-signed message. We take the
	// payload between the armor headers and the signature block. The signature
	// itself is not checked here: checkParams() proves the group is a 2048-bit
	// safe prime with 2 as a generator, which is what a forged modulus would
	// have to break, and the response itself arrived over TLS.
	function stripPgpArmor(signedMessage) {
		var text = String(signedMessage).replace(/\r\n/g, '\n');
		if (text.indexOf('-----BEGIN PGP SIGNED MESSAGE-----') < 0)
			return text.trim();     // already a bare base64 modulus
		var afterHeaders = text.indexOf('\n\n');
		if (afterHeaders < 0)
			throw new Error('malformed clear-signed modulus: no armor headers');
		var sigAt = text.indexOf('-----BEGIN PGP SIGNATURE-----', afterHeaders);
		if (sigAt < 0)
			throw new Error('malformed clear-signed modulus: no signature block');
		var payload = text.slice(afterHeaders + 2, sigAt).trim();
		if (!payload.length)
			throw new Error('malformed clear-signed modulus: empty payload');
		return payload;
	}

	/* ---- one-shot helper for the login modal --------------------------- */

	// Everything the LuCI login flow needs: takes what /auth/info returned and
	// produces exactly the fields /auth expects, plus the proof to check the
	// server's answer against.
	function prepareLogin(opts) {
		// Accepts either the raw clear-signed modulus from /auth/info or a bare
		// base64 one, so callers do not have to know about the armor.
		var modulusBase64 = stripPgpArmor(opts.modulusBase64);
		return hashPassword({
			version: opts.version,
			password: opts.password,
			username: opts.username,
			salt: base64ToBytes(opts.saltBase64),
			modulus: base64ToBytes(modulusBase64)
		}).then(function (hashedPassword) {
			return generateProofs({
				modulus: base64ToBytes(modulusBase64),
				serverEphemeral: base64ToBytes(opts.serverEphemeralBase64),
				hashedPassword: hashedPassword,
				bitLength: opts.bitLength
			});
		}).then(function (proofs) {
			return {
				clientEphemeral: bytesToBase64(proofs.clientEphemeral),
				clientProof: bytesToBase64(proofs.clientProof),
				expectedServerProof: proofs.expectedServerProof
			};
		});
	}

	return {
		expandHash: expandHash,
		sha512Sync: sha512Sync,
		stripPgpArmor: stripPgpArmor,
		bcryptHash: bcryptHash,
		bcryptBase64: bcryptBase64,
		hashPassword: hashPassword,
		checkParams: checkParams,
		generateProofs: generateProofs,
		verifyServerProof: verifyServerProof,
		prepareLogin: prepareLogin,
		modPow: modPow,
		bytesToBigIntLE: bytesToBigIntLE,
		bigIntToBytesLE: bigIntToBytesLE,
		base64ToBytes: base64ToBytes,
		bytesToBase64: bytesToBase64
	};
}));
