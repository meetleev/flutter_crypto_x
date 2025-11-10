import 'dart:typed_data';
import 'dart:convert' as convert;

import 'package:pointycastle/api.dart';
import 'package:pointycastle/asn1/asn1_object.dart';
import 'package:pointycastle/asn1/asn1_parser.dart';
import 'package:pointycastle/asn1/primitives/asn1_integer.dart';
import 'package:pointycastle/asn1/primitives/asn1_sequence.dart';
import 'package:pointycastle/asymmetric/api.dart';
import 'package:pointycastle/key_generators/api.dart';
import 'package:pointycastle/key_generators/rsa_key_generator.dart';

import '../crypto_secure_random.dart';

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

class RSAKeyPair<B extends RSAPublicKey, V extends RSAPrivateKey>
    extends AsymmetricKeyPair<B, V> {
  RSAKeyPair(super.publicKey, super.privateKey);

  /// export private key to PEM Format
  /// returns a base64 encoded [String] with standard PEM headers and footers
  String exportPrivateKey() {
    var topLevel = ASN1Sequence();
    topLevel.add(ASN1Integer(BigInt.zero));
    topLevel.add(ASN1Integer(privateKey.n));
    topLevel.add(ASN1Integer(privateKey.publicExponent));
    topLevel.add(ASN1Integer(privateKey.privateExponent));
    topLevel.add(ASN1Integer(privateKey.p));
    topLevel.add(ASN1Integer(privateKey.q));
    var dp = privateKey.privateExponent! % (privateKey.p! - BigInt.one);
    topLevel.add(ASN1Integer(dp));
    var dq = privateKey.privateExponent! % (privateKey.q! - BigInt.one);
    topLevel.add(ASN1Integer(dq));
    var iQ = privateKey.q!.modInverse(privateKey.p!);
    topLevel.add(ASN1Integer(iQ));
    var dataBase64 = convert.base64.encode(topLevel.encode());
    return '-----BEGIN RSA PRIVATE KEY-----\r$dataBase64\r-----END RSA PRIVATE KEY-----';
  }

  /// export public key to PEM Format
  /// returns a base64 encoded [String] with standard PEM headers and footers
  String exportPublicKey() {
    var topLevel = ASN1Sequence();
    topLevel.add(ASN1Integer(publicKey.modulus));
    topLevel.add(ASN1Integer(publicKey.publicExponent));
    var dataBase64 = convert.base64.encode(topLevel.encode());
    return '-----BEGIN RSA PUBLIC KEY-----\r$dataBase64\r-----END RSA PUBLIC KEY-----';
  }
}

class KeyPairsGenerator {
  /// generateRSAKeyPairs
  static RSAKeyPair generateRSAKeyPairs({int bitLength = 2048}) {
    final keyGen = RSAKeyGenerator();
    final secureRandom = SecureRandom('Fortuna')
      ..seed(KeyParameter(CryptoSecureRandom(32).bytes));
    keyGen.init(ParametersWithRandom(
        RSAKeyGeneratorParameters(BigInt.parse('65537'), bitLength, 64),
        secureRandom));

    // Use the generator
    final pair = keyGen.generateKeyPair();
    // Cast the generated key pair into the RSA key types
    final myPublic = pair.publicKey;
    final myPrivate = pair.privateKey;
    return RSAKeyPair<RSAPublicKey, RSAPrivateKey>(myPublic, myPrivate);
  }
}
