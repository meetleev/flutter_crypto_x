# crypto_x
[![Pub](https://img.shields.io/pub/v/crypto_x.svg?style=flat-square)](https://pub.dev/packages/crypto_x)
[![support](https://img.shields.io/badge/platform-android%20|%20ios%20|%20web%20|%20macos%20|%20windows%20|%20linux%20-blue.svg)](https://pub.dev/packages/crypto_x)

Advanced RSA based on pointycastle.

## Features

* RSA with PKCS1 and OAEP encoding.
* OAEP only supports encryption with public key and decryption with private key. For details, see [OAEPEncoding](https://github.com/bcgit/pc-dart/blob/master/lib/asymmetric/oaep.dart)

## Getting started

Add the package to your `pubspec.yaml`:

```yaml
dependencies:
  crypto_x: <latest_version>
```

## Usage

```dart
    var privateRSA = RSA(
        privateKey: 'privatePKCS8Key');
    var publicRSA = RSA(
        publicKey: 'publicPKCS8Key');
    CryptoSignature signature = privateRSA.encrypt(PlainBytes.fromString('hello world'), usePublic: false);
    String ciphertext = signature.base64;
    PlainBytes plainBytes = publicRSA.decrypt(signature);
    String plainText = plainBytes.toString();
```

[comment]: <> (## Additional information)
