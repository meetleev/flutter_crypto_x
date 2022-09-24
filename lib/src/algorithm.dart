import 'dart:typed_data';
import 'package:pointycastle/asymmetric/api.dart';

import 'crypto_bytes.dart';

/// Interface for the AESAlgorithm.
abstract class AESAlgorithm {
  /// Encrypt [plainBytes].
  CryptoBytes encrypt(CryptoBytes plainBytes,
      {CipherIV? iv, Uint8List? associatedData});

  /// Decrypt [encrypted] value.
  CryptoBytes decrypt(CryptoBytes encrypted,
      {CipherIV? iv, Uint8List? associatedData});
}

/// Interface for the RSAAlgorithm.
abstract class RSAAlgorithm {
  /// Encrypt [plainBytes].
  CryptoBytes encrypt(CryptoBytes plainBytes, {RSAPublicKey? key});

  /// Decrypt [encrypted] value.
  CryptoBytes decrypt(CryptoBytes encrypted, {RSAPrivateKey? key});
}

/// Interface for the SignerAlgorithm.
abstract class SignerAlgorithm {
  /// sign [plainBytes].
  CryptoBytes sign(CryptoBytes plainBytes, {RSAPrivateKey? key});

  /// verify encrypted [signature].
  bool verify(CryptoBytes signature, CryptoBytes plainBytes,
      {RSAPublicKey? key});
}
