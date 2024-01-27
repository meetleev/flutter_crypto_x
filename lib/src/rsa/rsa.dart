import 'dart:typed_data';

import 'package:crypto_x/src/rsa/rsa_key_helper.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/asymmetric/api.dart';
import 'package:pointycastle/asymmetric/oaep.dart';
import 'package:pointycastle/asymmetric/pkcs1.dart';
import 'package:pointycastle/asymmetric/rsa.dart';

import '../algorithm.dart';
import '../crypto_bytes.dart';

enum RSAEncoding {
  pkcs1,
  oaep,
}

class _BaseRSA {
  /// publicKey
  RSAPublicKey? publicKey;

  /// privateKey
  RSAPrivateKey? privateKey;

  PublicKeyParameter<RSAPublicKey>? get _publicKeyParams =>
      publicKey != null ? PublicKeyParameter(publicKey!) : null;

  PrivateKeyParameter<RSAPrivateKey>? get _privateKeyParams =>
      privateKey != null ? PrivateKeyParameter(privateKey!) : null;
  final AsymmetricBlockCipher _cipher;

  _BaseRSA({
    this.publicKey,
    this.privateKey,
    RSAEncoding encoding = RSAEncoding.pkcs1,
    DigestType oaepDigestType = DigestType.sha1,
  }) : _cipher = encoding == RSAEncoding.oaep
            ? OAEPEncoding.withCustomDigest(
                () => Digest(_digestNames[oaepDigestType]!), RSAEngine())
            : PKCS1Encoding(RSAEngine());
}

class RSA extends _BaseRSA implements RSAAlgorithm {
  /// encoding, uses [RSAEncoding.pkcs1] by default
  RSA({
    super.publicKey,
    super.privateKey,
    super.encoding,
    super.oaepDigestType,
  });

  /// create [RSA] fromKeyPairString
  factory RSA.fromKeyPairString({
    String? publicKeyPem,
    String? privateKeyPem,
    RSAEncoding encoding = RSAEncoding.pkcs1,
    DigestType oaepDigestType = DigestType.sha1,
  }) =>
      RSA(
          publicKey: (publicKeyPem ?? '').isNotEmpty
              ? RSAKeyParser.parseFromString(publicKeyPem!) as RSAPublicKey
              : null,
          privateKey: (publicKeyPem ?? '').isNotEmpty
              ? RSAKeyParser.parseFromString(publicKeyPem!) as RSAPrivateKey
              : null,
          encoding: encoding,
          oaepDigestType: oaepDigestType);

  /// Encrypting data [PlainBytes]
  @override
  CryptoBytes encrypt(CryptoBytes plainBytes, {RSAPublicKey? key}) {
    if (null != key) publicKey = key;
    assert(publicKey != null,
        'Can\'t encrypt without a publicKey key, null given.');
    _cipher
      ..reset()
      ..init(true, _publicKeyParams!);

    return CryptoBytes(_cipher.process(plainBytes.bytes));
  }

  /// Decrypting data [CryptoSignature]
  @override
  CryptoBytes decrypt(CryptoBytes signature, {RSAPrivateKey? key}) {
    if (null != key) privateKey = key;
    assert(privateKey != null,
        'Can\'t encrypt without a private key, null given.');

    _cipher
      ..reset()
      ..init(false, _privateKeyParams!);
    return CryptoBytes(_cipher.process(signature.bytes));
  }
}

/// DigestType
enum DigestType {
  md5,
  sha1,
  sha224,
  sha256,
  sha384,
  sha512,
}

const Map<DigestType, String> _digestIdentifierHexes = {
  DigestType.md5: '06082a864886f70d0205',
  DigestType.sha1: '06052b0e03021a',
  DigestType.sha224: '0609608648016503040204',
  DigestType.sha256: '0609608648016503040201',
  DigestType.sha384: '0609608648016503040202',
  DigestType.sha512: '0609608648016503040203'
};

const Map<DigestType, String> _digestNames = {
  DigestType.md5: 'MD5',
  DigestType.sha1: 'SHA-1',
  DigestType.sha224: 'SHA-224',
  DigestType.sha256: 'SHA-256',
  DigestType.sha384: 'SHA-384',
  DigestType.sha512: 'SHA-512'
};

class RSASigner extends _BaseRSA implements SignerAlgorithm {
  final Digest _digest;
  late Uint8List
      _digestIdentifier; // DER encoded with trailing tag (06)+length byte

  RSASigner({
    DigestType digestType = DigestType.sha256,
    super.publicKey,
    super.privateKey,
  }) : _digest = Digest(_digestNames[digestType]!) {
    _digestIdentifier = _hexStringToBytes(_digestIdentifierHexes[digestType]!);
  }

  /// create [RSASigner] fromKeyPairString
  factory RSASigner.fromKeyPairString({
    String? publicKeyPem,
    String? privateKeyPem,
    DigestType digestType = DigestType.sha256,
  }) =>
      RSASigner(
          digestType: digestType,
          publicKey: (publicKeyPem ?? '').isNotEmpty
              ? RSAKeyParser.parseFromString(publicKeyPem!) as RSAPublicKey
              : null,
          privateKey: (publicKeyPem ?? '').isNotEmpty
              ? RSAKeyParser.parseFromString(publicKeyPem!) as RSAPrivateKey
              : null);

  void _reset() {
    _digest.reset();
    _cipher.reset();
  }

  void _init(bool forSigning, CipherParameters params) {
    AsymmetricKeyParameter akparams;
    if (params is ParametersWithRandom) {
      akparams = params.parameters as AsymmetricKeyParameter<AsymmetricKey>;
    } else {
      akparams = params as AsymmetricKeyParameter<AsymmetricKey>;
    }
    var k = akparams.key as RSAAsymmetricKey;

    if (forSigning && (k is! RSAPrivateKey)) {
      throw ArgumentError('Signing requires private key');
    }

    if (!forSigning && (k is! RSAPublicKey)) {
      throw ArgumentError('Verification requires public key');
    }

    _reset();

    _cipher.init(forSigning, params);
  }

  Uint8List _generateSignature(Uint8List message) {
    var hash = Uint8List(_digest.digestSize);
    _digest.reset();
    _digest.update(message, 0, message.length);
    _digest.doFinal(hash, 0);

    var data = _derEncode(hash);
    var out = Uint8List(_cipher.outputBlockSize);
    var len = _cipher.processBlock(data, 0, data.length, out, 0);
    return out.sublist(0, len);
  }

  @override
  CryptoBytes sign(CryptoBytes plainBytes, {RSAPrivateKey? key}) {
    if (null != key) privateKey = key;
    _init(true, _privateKeyParams!);
    return CryptoBytes(_generateSignature(plainBytes.bytes));
  }

  @override
  bool verify(CryptoBytes signature, CryptoBytes plainBytes,
      {RSAPublicKey? key}) {
    if (null != key) publicKey = key;

    _init(false, _publicKeyParams!);

    var message = plainBytes.bytes;
    var hash = Uint8List(_digest.digestSize);
    _digest.reset();
    _digest.update(message, 0, message.length);
    _digest.doFinal(hash, 0);
    var sig = Uint8List(_cipher.outputBlockSize);
    try {
      final len = _cipher.processBlock(
          signature.bytes, 0, signature.bytes.length, sig, 0);
      sig = sig.sublist(0, len);
    } on ArgumentError {
      // Signature was tampered with so the RSA 'decrypted' block is totally
      // different to the original, causing [PKCS1Encoding._decodeBlock] to
      // throw an exception because it does not recognise it.
      return false;
    }

    var expected = _derEncode(hash);

    if (sig.length == expected.length) {
      for (var i = 0; i < sig.length; i++) {
        if (sig[i] != expected[i]) {
          return false;
        }
      }
      return true; //return Arrays.constantTimeAreEqual(sig, expected);
    } else if (sig.length == expected.length - 2) {
      // NULL left out
      var sigOffset = sig.length - hash.length - 2;
      var expectedOffset = expected.length - hash.length - 2;

      expected[1] -= 2; // adjust lengths
      expected[3] -= 2;

      var nonEqual = 0;

      for (var i = 0; i < hash.length; i++) {
        nonEqual |= (sig[sigOffset + i] ^ expected[expectedOffset + i]);
      }

      for (var i = 0; i < sigOffset; i++) {
        nonEqual |= (sig[i] ^ expected[i]); // check header less NULL
      }

      return nonEqual == 0;
    } else {
      return false;
    }
  }

  Uint8List _derEncode(Uint8List hash) {
    var out = Uint8List(2 + 2 + _digestIdentifier.length + 2 + 2 + hash.length);
    var i = 0;

    // header
    out[i++] = 48;
    out[i++] = out.length - 2;

    // algorithmIdentifier.header
    out[i++] = 48;
    out[i++] = _digestIdentifier.length + 2;

    // algorithmIdentifier.bytes
    out.setAll(i, _digestIdentifier);
    i += _digestIdentifier.length;

    // algorithmIdentifier.null
    out[i++] = 5;
    out[i++] = 0;

    // hash.header
    out[i++] = 4;
    out[i++] = hash.length;

    // hash.bytes
    out.setAll(i, hash);

    return out;
  }

  Uint8List _hexStringToBytes(String hex) {
    var result = Uint8List(hex.length ~/ 2);
    for (var i = 0; i < hex.length; i += 2) {
      var num = hex.substring(i, i + 2);
      var byte = int.parse(num, radix: 16);
      result[i ~/ 2] = byte;
    }
    return result;
  }
}
