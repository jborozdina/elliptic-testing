/// <reference path="node_modules/@types/node/index.d.ts" />

import * as fs from "fs";
import * as elliptic from 'elliptic';

import EDDSA = elliptic.eddsa;
import { DerivationFixtures } from './fixtures/DerivationFixtures';

var utils = elliptic.utils;
var assert = utils.assert;
var toArray = utils.toArray;

const derivations = DerivationFixtures.derivations;
const lines: string[] = fs.readFileSync('./fixtures/sign.input').toString().split('\n');
var ed25519 = new EDDSA('ed25519');
var expectedTests: number;

function toHex(arr: number[]) {
    return utils.toHex(arr).toUpperCase();
}

function testFactory1(i: number) {     
    var test = derivations[i];
    console.log('Can compute correct a and A for secret: ' + test.secret_hex);
    var secret = utils.toArray(test.secret_hex, 'hex');
    var key = ed25519.keyFromSecret(secret);
    assert(toHex(key.privBytes()) === test.a_hex, "Computation error - 'a'.");
    var xRecovered = toHex(ed25519.encodeInt(
                            ed25519.decodePoint(key.pubBytes()).getX()));
    assert(xRecovered === test.A_P.x, "Computation error - recovered x.");
    assert(toHex(key.pubBytes()) === test.A_hex, "Computation error - 'A'.");    
}

function testFactory2(i: number) {
    console.log("Test vector \n" + lines[i]);
    var split = lines[i].toUpperCase().split(':');
    var key = ed25519.keyFromSecret(split[0].slice(0, 64));
    var expectedPk = split[0].slice(64);

    assert(toHex(key.pubBytes()) === expectedPk, "Incorrect public key.");

    var msg = toArray(split[2], 'hex');
    var sig = key.sign(msg).toHex();
    var sigR = sig.slice(0, 64);
    var sigS = sig.slice(64);

    assert(sigR === split[3].slice(0, 64), "Incorrect signature R.");
    assert(sigS === split[3].slice(64, 128), "Incorrect signature S.");
    assert(key.verify(msg, sig), "Error key verification 1.");

    var forged = msg.length === 0 ? [ 0x78 ] /*ord('x')*/:
                msg.slice(0, msg.length - 1).concat(
                    (msg[(msg.length - 1)] + 1) % 256);

    assert((msg.length || 1) === forged.length, "Wrong message length.");
    assert(!key.verify(forged, sig), "Error key verification 2.");
}

// ed25519 derivations
expectedTests = 256;
console.log("Number of derivations: " + derivations.length);
assert(derivations.length === expectedTests, "Error loading derivations!");
for (var i = 0; i < expectedTests; i++) testFactory1(i);

// sign.input ed25519 test vectors
expectedTests = 1024;
console.log("Lines length: " + lines.length);
assert(lines.length === expectedTests + 1 /*blank line*/, "Error reading sign.input file!");
for (var i = 0; i < expectedTests; i++) testFactory2(i);

// EDDSA('ed25519')
assert(32 === ed25519.encodingLength, "Wrong encoding length.");
console.log("Can sign/verify message");
var secret = toArray(new Array(65).join('0'), 'hex');
assert(secret.length === 32, "Wrong secret key length.");
var msg = [ 0xB, 0xE, 0xE, 0xF ];
var key = ed25519.keyFromSecret(secret);
var sig = key.sign(msg).toHex();

var R = '8F1B9A7FDB22BCD2C15D4695B1CE2B063CBFAEC9B00BE360427BAC9533943F6C';
var S = '5F0B380FD7F2E43B70AB2FA29F6C6E3FFC1012710E174786814012324BF19B0C';

assert(sig.slice(0, 64) === R, "Incorrect signature R.");
assert(sig.slice(64) === S, "Incorrect signature S.");
assert(key.verify(msg, sig), "Error key verification 3.");

// KeyPair
var pair: elliptic.KeyPair2;
var secretStr = '00000000000000000000000000000000' +
                '00000000000000000000000000000000';
pair = ed25519.keyFromSecret(secretStr);
console.log("Can be created with keyFromSecret/keyFromPublic");
var pubKey = ed25519.keyFromPublic(toHex(pair.pubBytes()));
assert(pubKey.pub() instanceof ed25519.pointClass, "Wrong point class.");
assert(pubKey.pub().eq(pair.pub()));
console.log("#getSecret returns bytes with optional encoding");
assert(pair.getSecret() instanceof Array, "Secret is not an array.");
assert(pair.getSecret('hex') === secretStr, "Wrong secret key.");
console.log("#getPub returns bytes with optional encoding");
assert(pair.getPublic() instanceof Array, "Public is not an array");
assert(pair.getPublic('hex') === '3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29', "Wrong public key.");

console.log("All tests passed.");
