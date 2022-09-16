import 'dart:typed_data';
import 'dart:convert' as convert;

class CryptoSignature {
  final Uint8List _bytes;

  /// binary bytes
  Uint8List get bytes => _bytes;

  CryptoSignature(this._bytes);

  /// base64String
  String get base64 => convert.base64.encode(bytes);
}
