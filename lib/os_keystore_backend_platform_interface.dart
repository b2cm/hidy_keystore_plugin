import 'dart:typed_data';

import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'os_keystore_backend_method_channel.dart';

abstract class OsKeystoreBackendPlatform extends PlatformInterface {
  /// Constructs a OsKeystoreBackendPlatform.
  OsKeystoreBackendPlatform() : super(token: _token);

  static final Object _token = Object();

  static OsKeystoreBackendPlatform _instance = MethodChannelOsKeystoreBackend();

  /// The default instance of [OsKeystoreBackendPlatform] to use.
  ///
  /// Defaults to [MethodChannelOsKeystoreBackend].
  static OsKeystoreBackendPlatform get instance => _instance;

  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [OsKeystoreBackendPlatform] when
  /// they register themselves.
  static set instance(OsKeystoreBackendPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<String> generateKey(String curve, bool userAuthenticationRequired);

  Future<Uint8List> sign(String keyId, Uint8List data);

  Future<Map> getKeyInfo(String keyId);

  Future<bool> hasKey(String keyId);

  Future<bool> deleteKey(String keyId);

  Future<bool> verify(String keyId, Uint8List data, Uint8List signature);
}
