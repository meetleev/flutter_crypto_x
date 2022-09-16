# example

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
