import 'dart:typed_data';
import 'dart:convert' as convert;

class CryptoSignature {
  final Uint8List _bytes;

  /// binary bytes
  Uint8List get bytes => _bytes;

  CryptoSignature(this._bytes);

  /// Creates an CryptoSignature object from a Base64 string.
  CryptoSignature.fromBase64(String base64) : _bytes = convert.base64.decode(base64);

  /// Creates an CryptoSignature object from a UTF-8 string.
  CryptoSignature.fromUTF8(String input)
      : _bytes = Uint8List.fromList(convert.utf8.encode(input));

  /// Gets the Encrypted bytes as a Base64 representation.
  String get base64 => convert.base64.encode(bytes);
}
