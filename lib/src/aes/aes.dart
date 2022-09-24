import 'dart:typed_data';

import 'package:crypto_x/src/crypto_bytes.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/block/aes.dart';

import '../algorithm.dart';
import 'mode/cfb128.dart';
import 'mode/ofb128.dart';

enum AESMode {
  cbc,
  ecb,

  /// cfb 8bit
  cfb8,

  /// cfb 128bit
  cfb,

  /// ofb 128bit
  ofb,

  /// StreamCipher
  ctr, // p
}

const Map<AESMode, String> _modes = {
  AESMode.cbc: 'CBC',
  AESMode.cfb8: 'CFB-8',
  AESMode.cfb: 'CFB-128',
  AESMode.ctr: 'CTR',
  AESMode.ecb: 'ECB',
  AESMode.ofb: 'OFB-128',
};

BlockCipher? _buildCipher(AESMode mode, {PaddingEncoding? padding}) {
  if (AESMode.cfb == mode) {
    return CFB128BlockCipher(AESEngine());
  } else if (AESMode.ofb == mode) {
    return OFB128BlockCipher(AESEngine());
  }
  return null != padding
      ? PaddedBlockCipher('AES/${_modes[mode]}/${_paddings[padding]}')
      : BlockCipher('AES/${_modes[mode]}');
}

enum PaddingEncoding {
  pkcs7,
  ios7816_4,
}

const Map<PaddingEncoding, String> _paddings = {
  PaddingEncoding.pkcs7: 'PKCS7',
  PaddingEncoding.ios7816_4: 'ios7816-4',
};

class AES extends AESAlgorithm {
  final CipherKey key;
  final AESMode mode;
  final PaddingEncoding? padding;
  final BlockCipher? _cipher;

  final StreamCipher? _streamCipher;

  AES(
      {required this.key,
      this.mode = AESMode.cbc,
      this.padding = PaddingEncoding.pkcs7})
      : _streamCipher =
            AESMode.ctr == mode ? StreamCipher('AES/${_modes[mode]}') : null,
        _cipher =
            AESMode.ctr != mode ? _buildCipher(mode, padding: padding) : null;

  @override
  CryptoBytes encrypt(CryptoBytes plainBytes,
      {CipherIV? iv, Uint8List? associatedData}) {
    assert(null != iv, 'IV, null given.');
    if (null != _streamCipher) {
      _streamCipher!
        ..reset()
        ..init(true, _buildCipherParam(iv!, associatedData: associatedData));
      return CryptoBytes(_streamCipher!.process(plainBytes.bytes));
    }
    if (null == _cipher) {
      throw StateError('_cipher null.');
    }

    _cipher!
      ..reset()
      ..init(true, _buildCipherParam(iv!, associatedData: associatedData));
    if (null != padding) return CryptoBytes(_cipher!.process(plainBytes.bytes));
    return CryptoBytes(_processBlocks(_cipher!, plainBytes.bytes));
  }

  @override
  CryptoBytes decrypt(CryptoBytes encrypted,
      {CipherIV? iv, Uint8List? associatedData}) {
    assert(null != iv, 'IV, null given.');
    if (null != _streamCipher) {
      _streamCipher!
        ..reset()
        ..init(false, _buildCipherParam(iv!, associatedData: associatedData));
      return CryptoBytes(_streamCipher!.process(encrypted.bytes));
    }
    if (null == _cipher) {
      throw StateError('_cipher null.');
    }

    _cipher!
      ..reset()
      ..init(false, _buildCipherParam(iv!, associatedData: associatedData));

    if (null != padding) {
      return CryptoBytes(_cipher!.process(encrypted.bytes));
    }
    return CryptoBytes(_processBlocks(_cipher!, encrypted.bytes));
  }

  Uint8List _processBlocks(BlockCipher cipher, Uint8List input) {
    var output = Uint8List(input.lengthInBytes);

    for (int offset = 0; offset < input.lengthInBytes;) {
      offset += cipher.processBlock(input, offset, output, offset);
    }

    return output;
  }

  CipherParameters? _buildCipherParam(CipherIV iv,
      {Uint8List? associatedData}) {
    if (null != padding) {
      if (mode == AESMode.ecb) {
        return PaddedBlockCipherParameters(KeyParameter(key.bytes), null);
      }
      return PaddedBlockCipherParameters(
          ParametersWithIV<KeyParameter>(KeyParameter(key.bytes), iv.bytes),
          null);
    }
    if (mode == AESMode.ecb) {
      return KeyParameter(key.bytes);
    }
    return ParametersWithIV<KeyParameter>(KeyParameter(key.bytes), iv.bytes);
  }
}
