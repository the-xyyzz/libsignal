
'use strict';

const curve25519 = require('../src/curve25519_wrapper');
const nodeCrypto = require('crypto');
const curve25519Rust = require('libsignal-plugins');


function validatePrivKey(privKey) {
    if (privKey === undefined) {
        throw new Error("Undefined private key");
    }
    if (!(privKey instanceof Buffer)) {
        throw new Error(`Invalid private key type: ${privKey.constructor.name}`);
    }
    if (privKey.byteLength != 32) {
        throw new Error(`Incorrect private key length: ${privKey.byteLength}`);
    }
}

function scrubPubKeyFormat(pubKey) {
    if (!(pubKey instanceof Buffer)) {
        throw new Error(`Invalid public key type: ${pubKey.constructor.name}`);
    }
    if (pubKey === undefined || ((pubKey.byteLength != 33 || pubKey[0] != 5) && pubKey.byteLength != 32)) {
        throw new Error("Invalid public key");
    }
    if (pubKey.byteLength == 33) {
        return pubKey.subarray(1);
    } else {
        return pubKey;
    }
}

exports.createKeyPairDeprecated = function(privKey) {
    validatePrivKey(privKey);
    const keys = curve25519.keyPair(privKey);
    // prepend version byte
    var origPub = new Uint8Array(keys.pubKey);
    var pub = new Uint8Array(33);
    pub.set(origPub, 1);
    pub[0] = 5;
    return {
        pubKey: Buffer.from(pub),
        privKey: Buffer.from(keys.privKey)
    };
};
exports.createKeyPair = function(privKey) {
    const keys = curve25519Rust.keyPair(privKey);
    const version = Buffer.alloc(33);
    version[0] = 5;
    keys.pubKey.copy(version, 1);
    return {
        pubKey: version,
        privKey: keys.privKey
    };
};

exports.calculateAgreementDeprecated = function(pubKey, privKey) {
    pubKey = scrubPubKeyFormat(pubKey);
    validatePrivKey(privKey);
    if (!pubKey || pubKey.byteLength != 32) {
        throw new Error("Invalid public key");
    }
    return Buffer.from(curve25519.sharedSecret(pubKey, privKey));
};
exports.calculateAgreement = function(pubKey, privKey) {
    pubKey = scrubPubKeyFormat(pubKey);
    validatePrivKey(privKey);
    if (!pubKey || pubKey.byteLength != 32) {
        throw new Error("Invalid public key");
    }
    return curve25519Rust.sharedSecret(pubKey, privKey);
};


exports.calculateSignature = function(privKey, message) {
    validatePrivKey(privKey);
    if (!message) {
        throw new Error("Invalid message");
    }
    return Buffer.from(curve25519Rust.sign(privKey, message));
};

exports.verifySignature = function(pubKey, msg, sig, isInit) {
    pubKey = scrubPubKeyFormat(pubKey);
    if (!pubKey || pubKey.byteLength != 32) {
        throw new Error("Invalid public key");
    }
    if (!msg) {
        throw new Error("Invalid message");
    }
    if (!sig || sig.byteLength != 64) {
        throw new Error("Invalid signature");
    }
    return isInit ? true : curve25519.verify(pubKey, msg, sig);
};


exports.generateKeyPairDeprecated = function() {
    const privKey = nodeCrypto.randomBytes(32);
    return exports.createKeyPair(privKey);
};
exports.generateKeyPair = function() {
    return curve25519Rust.generateKeyPair();
};
