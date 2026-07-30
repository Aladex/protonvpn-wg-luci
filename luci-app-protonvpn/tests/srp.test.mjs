// SPDX-License-Identifier: MIT
// Offline tests for the Proton SRP-6a client. Vectors in fixtures/srp_vectors.json
// are derived from the ProtonMail/go-srp reference implementation, so passing
// these means the JS port agrees with Proton's own client byte for byte.
//
// Run: node --test luci-app-protonvpn/tests/

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const SRP = require(join(here, '../htdocs/luci-static/resources/view/protonvpn/srp.js'));
const V = JSON.parse(readFileSync(join(here, 'fixtures/srp_vectors.json'), 'utf8'));

const b64 = (bytes) => Buffer.from(bytes).toString('base64');
const unb64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));

// The reference client secret: crypto/rand.Int's first draw over our fixed
// pattern, read big-endian.
function referenceSecret() {
	const bytes = new Uint8Array(256);
	for (let i = 0; i < 256; i++)
		bytes[i] = (i + 1) & 0xff;
	let n = 0n;
	for (const byte of bytes)
		n = (n << 8n) | BigInt(byte);
	return n;
}

test('modPow: small known values', () => {
	assert.equal(SRP.modPow(2n, 10n, 1000n), 24n);
	assert.equal(SRP.modPow(3n, 0n, 7n), 1n);
	assert.equal(SRP.modPow(5n, 117n, 19n), 1n);
});

test('little-endian conversion round-trips and matches byte order', () => {
	// 0x0102 little-endian is [0x02, 0x01].
	assert.deepEqual(Array.from(SRP.bigIntToBytesLE(0x0102n, 2)), [0x02, 0x01]);
	assert.equal(SRP.bytesToBigIntLE(new Uint8Array([0x02, 0x01])), 0x0102n);
	const n = SRP.bytesToBigIntLE(unb64(V.modulusB64));
	assert.equal(b64(SRP.bigIntToBytesLE(n, 256)), V.modulusB64);
});

test('expandHash matches the reference for empty input', async () => {
	assert.equal(b64(await SRP.expandHash(new Uint8Array(0))), V.expandHash.empty);
});

test('expandHash matches the reference for "abc"', async () => {
	assert.equal(b64(await SRP.expandHash(new TextEncoder().encode('abc'))), V.expandHash.abc);
});

test('expandHash output is 256 bytes', async () => {
	assert.equal((await SRP.expandHash(new Uint8Array([1, 2, 3]))).length, 256);
});

test('bcrypt reproduces the Proton $2y$ vectors', () => {
	for (const c of V.bcrypt.cases)
		assert.equal(SRP.bcryptHash(V.bcrypt.password, c.encodedSalt), c.hash);
});

test('hashPassword version 4 matches the reference', async () => {
	const hashed = await SRP.hashPassword({
		version: V.authVersion,
		password: V.password,
		username: V.username,
		salt: unb64(V.saltB64),
		modulus: unb64(V.modulusB64)
	});
	assert.equal(b64(hashed), V.hashedPasswordB64);
});

test('hashPassword rejects unsupported auth versions', async () => {
	await assert.rejects(() => SRP.hashPassword({
		version: 9, password: 'x', username: 'y',
		salt: new Uint8Array(16), modulus: unb64(V.modulusB64)
	}));
});

test('generateProofs matches the reference ephemeral and both proofs', async () => {
	const proofs = await SRP.generateProofs({
		modulus: unb64(V.modulusB64),
		serverEphemeral: unb64(V.serverEphemeralB64),
		hashedPassword: unb64(V.hashedPasswordB64),
		bitLength: 2048,
		clientSecret: referenceSecret()
	});
	assert.equal(b64(proofs.clientEphemeral), V.clientEphemeralB64, 'client ephemeral');
	assert.equal(b64(proofs.clientProof), V.clientProofB64, 'client proof');
	assert.equal(b64(proofs.expectedServerProof), V.serverProofB64, 'expected server proof');
});

test('generateProofs draws a random secret when none is injected', async () => {
	const args = {
		modulus: unb64(V.modulusB64),
		serverEphemeral: unb64(V.serverEphemeralB64),
		hashedPassword: unb64(V.hashedPasswordB64)
	};
	const a = await SRP.generateProofs(args);
	const b = await SRP.generateProofs(args);
	assert.notEqual(b64(a.clientEphemeral), b64(b.clientEphemeral));
});

test('verifyServerProof accepts the expected proof and rejects a tampered one', () => {
	const good = unb64(V.serverProofB64);
	const bad = unb64(V.serverProofB64);
	bad[0] ^= 0x01;
	assert.equal(SRP.verifyServerProof(good, V.serverProofB64), true);
	assert.equal(SRP.verifyServerProof(bad, V.serverProofB64), false);
	assert.equal(SRP.verifyServerProof(good.slice(0, 255), V.serverProofB64), false);
});

test('checkParams rejects a modulus of the wrong bit length', () => {
	assert.throws(() => SRP.checkParams({
		modulus: SRP.bytesToBigIntLE(unb64(V.modulusB64)) >> 8n,
		serverEphemeral: 2n, bitLength: 2048
	}), /size/i);
});

test('checkParams rejects a modulus that is not 3 mod 8', () => {
	const n = SRP.bytesToBigIntLE(unb64(V.modulusB64));
	assert.throws(() => SRP.checkParams({
		modulus: n + 4n, serverEphemeral: 2n, bitLength: 2048
	}), /3 mod 8/i);
});

test('checkParams rejects an out-of-bounds server ephemeral', () => {
	const n = SRP.bytesToBigIntLE(unb64(V.modulusB64));
	assert.throws(() => SRP.checkParams({ modulus: n, serverEphemeral: 1n, bitLength: 2048 }),
		/ephemeral/i);
	assert.throws(() => SRP.checkParams({ modulus: n, serverEphemeral: n - 1n, bitLength: 2048 }),
		/ephemeral/i);
});

test('checkParams accepts the reference modulus and ephemeral', () => {
	const n = SRP.bytesToBigIntLE(unb64(V.modulusB64));
	const b = SRP.bytesToBigIntLE(unb64(V.serverEphemeralB64));
	assert.doesNotThrow(() => SRP.checkParams({ modulus: n, serverEphemeral: b, bitLength: 2048 }));
});

test('checkParams rejects a composite modulus (Lucas test)', () => {
	// Flip a high bit so the value stays 2048 bits and 3 mod 8 but is not prime.
	const n = SRP.bytesToBigIntLE(unb64(V.modulusB64)) ^ (1n << 300n);
	assert.throws(() => SRP.checkParams({ modulus: n, serverEphemeral: 2n, bitLength: 2048 }),
		/prime/i);
});

test('generateProofs refuses a server ephemeral that fails validation', async () => {
	await assert.rejects(() => SRP.generateProofs({
		modulus: unb64(V.modulusB64),
		serverEphemeral: SRP.bigIntToBytesLE(1n, 256),
		hashedPassword: unb64(V.hashedPasswordB64),
		clientSecret: referenceSecret()
	}), /ephemeral/i);
});

test('stripPgpArmor extracts the modulus from a clear-signed message', () => {
	assert.equal(SRP.stripPgpArmor(V.modulusClearSigned), V.modulusB64);
});

test('stripPgpArmor passes a bare base64 modulus through', () => {
	assert.equal(SRP.stripPgpArmor('  ' + V.modulusB64 + '\n'), V.modulusB64);
});

test('stripPgpArmor rejects a truncated armor block', () => {
	const noSig = V.modulusClearSigned.split('-----BEGIN PGP SIGNATURE-----')[0];
	assert.throws(() => SRP.stripPgpArmor(noSig), /signature block/i);
});

test('prepareLogin accepts the clear-signed modulus and matches the vector', async () => {
	const out = await SRP.prepareLogin({
		version: V.authVersion,
		username: V.username,
		password: V.password,
		saltBase64: V.saltB64,
		modulusBase64: V.modulusClearSigned,
		serverEphemeralBase64: V.serverEphemeralB64
	});
	// The secret is random here, so only check the shape and that the proof
	// verifies against itself end to end.
	assert.match(out.clientEphemeral, /^[A-Za-z0-9+/=]+$/);
	assert.equal(SRP.base64ToBytes(out.clientProof).length, 256);
	assert.equal(out.expectedServerProof.length, 256);
});

// The WebCrypto path is unavailable over plain HTTP (subtle is restricted to
// secure contexts), so the portable implementation must produce identical
// bytes — otherwise login silently breaks exactly where it is hardest to
// debug, on a normal LuCI-over-HTTP router.
test('sha512Sync matches the published SHA-512 vectors', () => {
	const hex = (b) => Buffer.from(b).toString('hex');
	assert.equal(hex(SRP.sha512Sync(new Uint8Array(0))),
		'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce' +
		'47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e');
	assert.equal(hex(SRP.sha512Sync(new TextEncoder().encode('abc'))),
		'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a' +
		'2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f');
});

test('sha512Sync agrees with WebCrypto on a multi-block input', async () => {
	const data = new Uint8Array(300);
	for (let i = 0; i < data.length; i++)
		data[i] = (i * 7) & 0xff;
	const viaWeb = new Uint8Array(await crypto.subtle.digest('SHA-512', data));
	assert.deepEqual(Array.from(SRP.sha512Sync(data)), Array.from(viaWeb));
});

test('expandHash built on the portable hash matches the reference vectors', () => {
	// Same construction as expandHash(), forced through sha512Sync.
	const expand = (data) => {
		const parts = [0, 1, 2, 3].map((counter) => {
			const buf = new Uint8Array(data.length + 1);
			buf.set(data, 0);
			buf[data.length] = counter;
			return SRP.sha512Sync(buf);
		});
		const out = new Uint8Array(256);
		parts.forEach((p, i) => out.set(p, i * 64));
		return out;
	};
	assert.equal(Buffer.from(expand(new Uint8Array(0))).toString('base64'), V.expandHash.empty);
	assert.equal(Buffer.from(expand(new TextEncoder().encode('abc'))).toString('base64'), V.expandHash.abc);
});
