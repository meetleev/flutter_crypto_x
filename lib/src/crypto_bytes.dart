import 'dart:typed_data';
import 'dart:convert' as convert;

import 'package:pointycastle/api.dart';
import 'package:pointycastle/key_derivators/api.dart';
import 'package:pointycastle/key_derivators/pbkdf2.dart';

import 'crypto_secure_random.dart';

class CryptoBytes {
  final Uint8List _bytes;

  /// binary bytes
  Uint8List get bytes => _bytes;

  CryptoBytes(this._bytes);

  /// Creates an CryptoSignature object from a Base64 string.
  CryptoBytes.fromBase64(String base64)
      : _bytes = convert.base64.decode(base64);

  /// Creates an CryptoSignature object from a UTF-8 string.
  CryptoBytes.fromUTF8(String input)
      : _bytes = Uint8List.fromList(convert.utf8.encode(input));

  /// Gets the Encrypted bytes as a Base64 representation.
  String get base64 => convert.base64.encode(bytes);

  @override
  String toString() {
    return convert.utf8.decode(bytes, allowMalformed: true);
  }
}

class CipherIV extends CryptoBytes {
  CipherIV(super.bytes);

  /// Creates an CipherIV object from a Base64 string.
  CipherIV.fromBase64(String base64) : super(convert.base64.decode(base64));

  /// Creates an CipherIV object from a UTF-8 string.
  CipherIV.fromUTF8(String input)
      : super(Uint8List.fromList(convert.utf8.encode(input)));

  /// The key is filled with [length] bytes generated by the Random.secure() generator
  CipherIV.fromRandom(int length) : super(CryptoSecureRandom(length).bytes);
}

class CipherKey extends CryptoBytes {
  CipherKey(super.bytes);

  /// Creates an CipherKey object from a Base64 string.
  CipherKey.fromBase64(String base64) : super(convert.base64.decode(base64));

  /// Creates an CipherKey object from a UTF-8 string.
  CipherKey.fromUTF8(String input)
      : super(Uint8List.fromList(convert.utf8.encode(input)));

  /// The key is filled with [length] bytes generated by the Random.secure() generator
  CipherKey.fromRandom(int length) : super(CryptoSecureRandom(length).bytes);

  CipherKey formPBKDF2(int keyLength,
      {int iterationCount = 100, Uint8List? salt}) {
    salt ??= CryptoSecureRandom(keyLength).bytes;
    final params = Pbkdf2Parameters(salt, iterationCount, keyLength);
    final pbkdf2 = PBKDF2KeyDerivator(Mac('SHA-1/HMAC'))..init(params);
    return CipherKey(pbkdf2.process(_bytes));
  }
}
