import 'dart:typed_data';
import 'dart:convert' as convert;

class PlainBytes {
  /// binary bytes
  final Uint8List bytes;

  PlainBytes(this.bytes);

  /// create plainBytes from String
  PlainBytes.fromString(String value) : bytes = Uint8List.fromList(convert.utf8.encode(value));

  @override
  toString() => convert.utf8.decode(bytes, allowMalformed: true);
}
