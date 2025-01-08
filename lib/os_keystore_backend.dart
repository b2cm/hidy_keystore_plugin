import 'dart:typed_data';

import 'package:os_keystore_backend/biometric_prompt_data.dart';

import 'os_keystore_backend_platform_interface.dart';

class OsKeystoreBackend {
  /// Generates a key using the specific elliptic [curve] and returns its identifier in the KeyStore System
  ///
  /// Valid values for [curve] are `secp256r1`, `secp384r1` and `secp521r1`.
  Future<String> generateKey(String curve, bool userAuthenticationRequired) {
    return OsKeystoreBackendPlatform.instance
        .generateKey(curve, userAuthenticationRequired);
  }

  /// Sign the given [data] with the key identified by [keyId]
  ///
  /// The returned signature is a plain signature (for ecdsa this means the concatenation of r and s value)
  ///
  /// [promptData] is used to customize the System prompt for biometric authentication, when a key with userAuthenticationRequired=true is used. Maybe Android Only?
  Future<Uint8List> sign(String keyId, Uint8List data,
      [BiometricPromptData? promptData]) {
    return OsKeystoreBackendPlatform.instance.sign(keyId, data, promptData);
  }

  /// Verifies the given [signature] over [data] with the key identified by [keyId]
  ///
  /// [signature] has to be a plain signature (for ecdsa this means the concatenation of r and s value)
  /// without any additional encoding (e.g. ASN1)
  Future<bool> verify(String keyId, Uint8List data, Uint8List signature) {
    return OsKeystoreBackendPlatform.instance.verify(keyId, data, signature);
  }

  /// Returns metadata about the key identified by [keyId].
  ///
  /// This metadata has jwk format. On android the keys kty, key_ops, x5c (to provide the public key),
  /// userAuthenticationRequired and securityLevel (API-Level 31 and above) or insideSecureHardware are used
  Future<Map> getKeyInfo(String keyId) {
    return OsKeystoreBackendPlatform.instance.getKeyInfo(keyId);
  }

  /// Returns whether the KeyStore controls the key identified by [keyId]
  Future<bool> hasKey(String keyId) {
    return OsKeystoreBackendPlatform.instance.hasKey(keyId);
  }

  Future<bool> deleteKey(String keyId) {
    return OsKeystoreBackendPlatform.instance.deleteKey(keyId);
  }
}
