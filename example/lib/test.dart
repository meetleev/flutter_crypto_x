import 'package:crypto_x/crypto_x.dart';

class RSATest {
  final RSA privateRSA, publicRSA;


  RSATest({
    required this.privateRSA,
    required this.publicRSA,
  });

  privateEncryptToPublicDecrypt(String value) {
    CryptoSignature signature = privateRSA.encrypt(PlainBytes.fromString(value), usePublic: false);
    print('privateEncryptToPublicDecrypt:signature=[${signature.base64}]');
    PlainBytes plainBytes = publicRSA.decrypt(signature);
    print('privateEncryptToPublicDecrypt:plain=[${plainBytes.toString()}]');
  }

  publicEncryptToPrivateDecrypt(String value) {
    CryptoSignature signature = publicRSA.encrypt(PlainBytes.fromString(value));
    print('publicEncryptToPrivateDecrypt:signature=[${signature.base64}]');
    PlainBytes plainBytes = privateRSA.decrypt(signature, usePublic: false);
    print('publicEncryptToPrivateDecrypt:plain=[${plainBytes.toString()}]');
  }
}
