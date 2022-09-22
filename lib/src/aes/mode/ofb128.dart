import 'dart:typed_data';

import 'package:crypto_x/src/aes/base_block_cipher.dart';
import 'package:pointycastle/api.dart';

class OFB128BlockCipher extends BaseBlockCipher {
  @override
  final int blockSize = 16;

  final BlockCipher _aesEngineCipher;

  final Uint8List _iv;
  final Uint8List? _ofbV;
  final Uint8List? _ofbOutV;

  OFB128BlockCipher(this._aesEngineCipher)
      : _iv = Uint8List(_aesEngineCipher.blockSize),
        _ofbV = Uint8List(_aesEngineCipher.blockSize),
        _ofbOutV = Uint8List(_aesEngineCipher.blockSize);

  @override
  String get algorithmName =>
      '${_aesEngineCipher.algorithmName}/OFB-${blockSize * 8}';

  @override
  void reset() {
    _ofbV!.setRange(0, _iv.length, _iv);
    _aesEngineCipher.reset();
  }

  /// Initialise the cipher and, possibly, the initialisation vector (IV). If an IV isn't passed as part of the parameter, the
  /// IV will be all zeros. An IV which is too short is handled in FIPS compliant fashion.
  @override
  void init(bool forEncryption, CipherParameters? params) {
    if (params is ParametersWithIV) {
      var ivParam = params;
      var iv = ivParam.iv;

      if (iv.length < _iv.length) {
        // prepend the supplied IV with zeros (per FIPS PUB 81)
        var offset = _iv.length - iv.length;
        _iv.fillRange(0, offset, 0);
        _iv.setAll(offset, iv);
      } else {
        _iv.setRange(0, _iv.length, iv);
      }

      reset();

      // if null it's an IV changed only.
      if (ivParam.parameters != null) {
        _aesEngineCipher.init(true, ivParam.parameters);
      }
    } else {
      _aesEngineCipher.init(true, params);
    }
  }

  @override
  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    var n = blockSize;
    if ((inpOff + blockSize) > inp.length) {
      n = blockSize - (inpOff + blockSize - inp.length);
    }

    _aesEngineCipher.processBlock(_ofbV!, 0, _ofbOutV!, 0);

    // XOR the ofbV with the plaintext producing the cipher text (and the next input block).
    for (var i = 0; i < n; i++) {
      out[outOff + i] = _ofbOutV![i] ^ inp[inpOff + i];
    }

    // change over the input block.
    var offset = _ofbV!.length - blockSize;
    _ofbV!.setRange(0, offset, _ofbV!.sublist(blockSize));
    _ofbV!.setRange(offset, _ofbV!.length, _ofbOutV!);

    return n;
  }
}
