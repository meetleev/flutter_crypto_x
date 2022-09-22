# crypto_x
[![Pub](https://img.shields.io/pub/v/crypto_x.svg?style=flat-square)](https://pub.dev/packages/crypto_x)
[![support](https://img.shields.io/badge/platform-android%20|%20ios%20|%20web%20|%20macos%20|%20windows%20|%20linux%20-blue.svg)](https://pub.dev/packages/crypto_x)

A Dart library for encryption and decryption. Advanced RSA, AES based on pointycastle.

## Features

* RSA with PKCS1 and OAEP encoding.
* Generate RSA KeyPairs and import to pem format.

## Getting started

Add the package to your `pubspec.yaml`:

```yaml
dependencies:
  crypto_x: <latest_version>
```

## Usage

### AES

#### Supported modes are:
- CBC `AESMode.cbc`
- CFB-8 `AESMode.cfb8`
- CFB-128 `AESMode.cfb`
- CTR `AESMode.ctr`
- ECB `AESMode.ecb`
- OFB-128 `AESMode.ofb`

```dart
    final key = CipherKey.fromUtf8('your key................');
    final iv = CipherIV.fromLength(16);
    var aes = AES(key: key, mode: AESMode.cbc);
    CryptoBytes encrypted = aes.encrypt(CryptoBytes.fromUTF8('hello world.'), iv: iv);
    String encryptedBase64 = decrypted.base64;
    CryptoBytes decrypted = aes.decrypt(encrypted, iv: iv);
    String plainText = decrypted.toString();
```

### RSA
```dart
    var privateRSA = RSA(
        privateKey: privateKey);
    var publicRSA = RSA(
        publicKey: publicKey);
    CryptoBytes signature = publicRSA.encrypt(CryptoBytes.fromUTF8('hello world'));
    String ciphertext = signature.base64;
    CryptoBytes plainBytes = publicRSA.decrypt(signature);
    String plainText = plainBytes.toString();
```

[comment]: <> (## Additional information)
