import 'dart:math';
import 'dart:typed_data';

class CryptoSecureRandom {
  static final Random _generator = Random.secure();
  final Uint8List _bytes;

  CryptoSecureRandom(int length)
      : _bytes = Uint8List.fromList(
            List.generate(length, (i) => _generator.nextInt(256)));

  Uint8List get bytes => _bytes;
}
