import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'os_keystore_backend_platform_interface.dart';

/// An implementation of [OsKeystoreBackendPlatform] that uses method channels.
class MethodChannelOsKeystoreBackend extends OsKeystoreBackendPlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('os_keystore_backend');

  @override
  Future<String> generateKey(
      String curve, bool userAuthenticationRequired) async {
    final keyId = await methodChannel.invokeMethod<String>(
        'generateKey', <String, dynamic>{
      'curve': curve,
      'userAuthenticationRequired': userAuthenticationRequired
    });
    if (keyId != null) {
      return keyId;
    } else {
      throw Exception('Failed to generate Key');
    }
  }

  @override
  Future<Uint8List> sign(String keyId, Uint8List data) async {
    final signature = await methodChannel.invokeMethod<Uint8List>(
        'sign', <String, dynamic>{'keyId': keyId, 'data': data});
    if (signature != null) {
      return signature;
    } else {
      throw Exception('Signature Generation failed');
    }
  }

  @override
  Future<Map> getKeyInfo(String keyId) async {
    final info = await methodChannel
        .invokeMethod<Map>('getKeyInfo', <String, dynamic>{'keyId': keyId});
    if (info != null) {
      return info;
    } else {
      throw Exception('Fetching information failed');
    }
  }

  @override
  Future<bool> hasKey(String keyId) async {
    final info = await methodChannel
        .invokeMethod<bool>('hasKey', <String, dynamic>{'keyId': keyId});
    if (info != null) {
      return info;
    } else {
      throw Exception('Fetching information failed');
    }
  }

  @override
  Future<bool> deleteKey(String keyId) async {
    final info = await methodChannel
        .invokeMethod<bool>('deleteKey', <String, dynamic>{'keyId': keyId});
    if (info != null) {
      return info;
    } else {
      throw Exception('Fetching information failed');
    }
  }
}
