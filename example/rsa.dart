import 'package:crypto_x/crypto_x.dart';
import 'package:flutter/services.dart';

class RSATest {
  final RSA privateRSA, publicRSA;

  RSATest({
    required this.privateRSA,
    required this.publicRSA,
  });

  privateEncryptToPublicDecrypt(String value) {
    CryptoSignature signature =
        privateRSA.encrypt(PlainBytes.fromString(value), usePublic: false);
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

enum RSAKeyFormat { pkcs1, pkcs8 }

class Test {
  late String _privatePKCS1Key, _publicPKCS1Key;
  late String _privatePKCS8Key, _publicPKCS8Key;

  Future<void> loadCertsAndTest() async {
    _privatePKCS1Key =
        await rootBundle.loadString('assets/certs/private_pkcs1.pem');
    _publicPKCS1Key =
        await rootBundle.loadString('assets/certs/public_pkcs1.pem');
    _privatePKCS8Key =
        await rootBundle.loadString('assets/certs/private_pkcs8.pem');
    _publicPKCS8Key =
        await rootBundle.loadString('assets/certs/public_pkcs8.pem');
    _test();
  }

  void _rasTest(
      {RSAKeyFormat privateRSAKeyFormat = RSAKeyFormat.pkcs1,
      RSAKeyFormat publicRSAKeyFormat = RSAKeyFormat.pkcs1,
      RSAEncoding encoding = RSAEncoding.pkcs1}) {
    print('----_rasTest--encoding:[$encoding]----');
    var privatePKCS1 = RSA(
        privateKey: RSAKeyFormat.pkcs1 == privateRSAKeyFormat
            ? _privatePKCS1Key
            : _privatePKCS8Key,
        encoding: encoding);
    var publicPKCS1 = RSA(
        publicKey: RSAKeyFormat.pkcs1 == publicRSAKeyFormat
            ? _publicPKCS1Key
            : _publicPKCS8Key,
        encoding: encoding);
    var rSATest = RSATest(
      privateRSA: privatePKCS1,
      publicRSA: publicPKCS1,
    );
    rSATest.publicEncryptToPrivateDecrypt(
        'public $encoding:[$publicRSAKeyFormat]=>[$privateRSAKeyFormat]');
    rSATest.privateEncryptToPublicDecrypt(
        'private $encoding:[$privateRSAKeyFormat]=>[$publicRSAKeyFormat]');
  }

  void _test() {
    /// RSAKeyFormat pkcs1->pkcs1 RSAEncoding pkcs1
    _rasTest();

    /// RSAKeyFormat pkcs1->pkcs8 RSAEncoding pkcs1
    _rasTest(publicRSAKeyFormat: RSAKeyFormat.pkcs8);

    /// RSAKeyFormat pkcs8->pkcs1 RSAEncoding pkcs1
    _rasTest(privateRSAKeyFormat: RSAKeyFormat.pkcs8);

    /// RSAKeyFormat pkcs8->pkcs8 RSAEncoding pkcs1
    _rasTest(
        privateRSAKeyFormat: RSAKeyFormat.pkcs8,
        publicRSAKeyFormat: RSAKeyFormat.pkcs8);

    /// RSAKeyFormat pkcs1->pkcs1 RSAEncoding oaep
    // _rasTest(encoding: RSAEncoding.oaep);

    /// RSAKeyFormat pkcs1->pkcs8 RSAEncoding oaep
    // _rasTest(publicRSAKeyFormat: RSAKeyFormat.pkcs8, encoding: RSAEncoding.oaep);

    /// RSAKeyFormat pkcs8->pkcs1 RSAEncoding oaep
    // _rasTest(privateRSAKeyFormat: RSAKeyFormat.pkcs8, encoding: RSAEncoding.oaep);

    /// RSAKeyFormat pkcs8->pkcs8 RSAEncoding oaep
    // _rasTest(
    //     privateRSAKeyFormat: RSAKeyFormat.pkcs8,
    //     publicRSAKeyFormat: RSAKeyFormat.pkcs8,
    //     encoding: RSAEncoding.oaep);
  }
}
