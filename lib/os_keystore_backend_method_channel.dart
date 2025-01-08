import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:os_keystore_backend/biometric_prompt_data.dart';

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
  Future<Uint8List> sign(
      String keyId, Uint8List data, BiometricPromptData? promptData) async {
    final signature =
        await methodChannel.invokeMethod<Uint8List>('sign', <String, dynamic>{
      'keyId': keyId,
      'data': data,
      'biometricPromptTitle': promptData?.title,
      'biometricPromptSubtitle': promptData?.subtitle,
      'biometricPromptNegative': promptData?.negativeButton
    });
    if (signature != null) {
      return signature;
    } else {
      throw Exception('Signature Generation failed');
    }
  }

  @override
  Future<bool> verify(String keyId, Uint8List data, Uint8List signature) async {
    final verified = await methodChannel.invokeMethod<bool>(
        'verify', <String, dynamic>{
      'keyId': keyId,
      'data': data,
      'signature': signature
    });
    if (verified != null) {
      return verified;
    } else {
      throw Exception('Verification failed');
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
