import 'dart:typed_data';
import 'dart:convert' as convert;

import 'package:pointycastle/api.dart';
import 'package:pointycastle/asn1/asn1_object.dart';
import 'package:pointycastle/asn1/asn1_parser.dart';
import 'package:pointycastle/asn1/primitives/asn1_integer.dart';
import 'package:pointycastle/asn1/primitives/asn1_sequence.dart';
import 'package:pointycastle/asymmetric/api.dart';
import 'package:pointycastle/asymmetric/oaep.dart';
import 'package:pointycastle/asymmetric/pkcs1.dart';
import 'package:pointycastle/asymmetric/rsa.dart';

import 'plain_bytes.dart';
import 'crypto_signature.dart';

enum RSAEncoding {
  pkcs1,
  oaep,
}

enum RSADigest {
  sha1,
  sha256,
}

class RSA {
  /// publicKey
  final RSAPublicKey? publicKey;

  /// privateKey
  final RSAPrivateKey? privateKey;

  PublicKeyParameter<RSAPublicKey>? get _publicKeyParams =>
      publicKey != null ? PublicKeyParameter(publicKey!) : null;

  PrivateKeyParameter<RSAPrivateKey>? get _privateKeyParams =>
      privateKey != null ? PrivateKeyParameter(privateKey!) : null;
  final AsymmetricBlockCipher _cipher;

  /// encoding, uses [RSAEncoding.pkcs1] by default
  RSA({
    String? publicKey,
    String? privateKey,
    RSAEncoding encoding = RSAEncoding.pkcs1,
    RSADigest digest = RSADigest.sha1,
  })  : publicKey = (publicKey ?? '').isNotEmpty
            ? RSAKeyParser.parseFromString(publicKey!) as RSAPublicKey
            : null,
        privateKey = (privateKey ?? '').isNotEmpty
            ? RSAKeyParser.parseFromString(privateKey!) as RSAPrivateKey
            : null,
        _cipher = encoding == RSAEncoding.oaep
            ? digest == RSADigest.sha1
                ? OAEPEncoding(RSAEngine())
                : OAEPEncoding.withSHA256(RSAEngine())
            : PKCS1Encoding(RSAEngine());

  /// Encrypting data [PlainBytes], uses public key by default
  CryptoSignature encrypt(PlainBytes plainBytes, {bool usePublic = true}) {
    if (usePublic) {
      assert(publicKey != null,
          'Can\'t encrypt without a publicKey key, null given.');
    } else {
      assert(privateKey != null,
          'Can\'t encrypt without a private key, null given.');
    }
    _cipher
      ..reset()
      ..init(true, usePublic ? _publicKeyParams! : _privateKeyParams!);

    return CryptoSignature(_cipher.process(plainBytes.bytes));
  }

  /// Decrypting data [CryptoSignature], uses public key by default
  PlainBytes decrypt(CryptoSignature signature, {bool usePublic = true}) {
    if (usePublic) {
      assert(publicKey != null,
          'Can\'t encrypt without a publicKey key, null given.');
    } else {
      assert(privateKey != null,
          'Can\'t encrypt without a private key, null given.');
    }

    _cipher
      ..reset()
      ..init(false, usePublic ? _publicKeyParams! : _privateKeyParams!);

    return PlainBytes(_cipher.process(signature.bytes));
  }
}

/// RSA PEM parser.
class RSAKeyParser {
  static RSAAsymmetricKey parseFromString(String key) {
    RSAKeyParser rsaKeyParser = RSAKeyParser();
    return rsaKeyParser.parse(key);
  }

  /// Parses the PEM key no matter it is public or private, it will figure it out.
  RSAAsymmetricKey parse(String key) {
    final rows = key.split(RegExp(r'\r\n?|\n'));
    final header = rows.first;

    if (header == '-----BEGIN RSA PUBLIC KEY-----') {
      return _parsePublic(_parseSequence(rows));
    }

    if (header == '-----BEGIN PUBLIC KEY-----') {
      return _parsePublic(_pkcs8PublicSequence(_parseSequence(rows)));
    }

    if (header == '-----BEGIN RSA PRIVATE KEY-----') {
      return _parsePrivate(_parseSequence(rows));
    }

    if (header == '-----BEGIN PRIVATE KEY-----') {
      return _parsePrivate(_pkcs8PrivateSequence(_parseSequence(rows)));
    }

    throw FormatException('Unable to parse key, invalid format.', header);
  }

  /// 0 modulus(n), 1 publicExponent(e)
  RSAAsymmetricKey _parsePublic(ASN1Sequence sequence) {
    final List<ASN1Integer> asn1IntList =
        sequence.elements!.cast<ASN1Integer>();
    final modulus = asn1IntList.elementAt(0).integer;
    final exponent = asn1IntList.elementAt(1).integer;
    return RSAPublicKey(modulus!, exponent!);
  }

  /// 0 version, 1 modulus(n), 2 publicExponent(e), 3 privateExponent(d), 4 prime1(p), 5 prime2(q)
  /// 6 exponent1(d mod (p-1)), 7 exponent2 (d mod (q-1)), 8 coefficient
  RSAAsymmetricKey _parsePrivate(ASN1Sequence sequence) {
    final List<ASN1Integer> asn1IntList =
        sequence.elements!.cast<ASN1Integer>();
    final modulus = asn1IntList.elementAt(1).integer;
    final exponent = asn1IntList.elementAt(3).integer;
    final p = asn1IntList.elementAt(4).integer;
    final q = asn1IntList.elementAt(5).integer;
    return RSAPrivateKey(modulus!, exponent!, p, q);
  }

  ASN1Sequence _parseSequence(List<String> rows) {
    final keyText = rows
        .skipWhile((row) => row.startsWith('-----BEGIN'))
        .takeWhile((row) => !row.startsWith('-----END'))
        .map((row) => row.trim())
        .join('');

    final keyBytes = Uint8List.fromList(convert.base64.decode(keyText));
    final asn1Parser = ASN1Parser(keyBytes);

    return asn1Parser.nextObject() as ASN1Sequence;
  }

  ASN1Sequence _pkcs8PublicSequence(ASN1Sequence sequence) {
    final ASN1Object bitString = sequence.elements![1];
    final bytes = bitString.valueBytes!.sublist(1);
    final parser = ASN1Parser(Uint8List.fromList(bytes));

    return parser.nextObject() as ASN1Sequence;
  }

  ASN1Sequence _pkcs8PrivateSequence(ASN1Sequence sequence) {
    final ASN1Object bitString = sequence.elements![2];
    final bytes = bitString.valueBytes!;
    final parser = ASN1Parser(bytes);

    return parser.nextObject() as ASN1Sequence;
  }
}
