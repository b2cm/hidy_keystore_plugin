import 'dart:typed_data';

import 'biometric_prompt_data.dart';
import 'os_keystore_backend_platform_interface.dart';

class OsKeystoreBackend {
  /// Generates a key using the specific elliptic [curve] and returns its identifier in the KeyStore System
  ///
  /// Valid values for [curve] are `secp256r1`, `secp384r1` and `secp521r1`.
  /// Pay attention to the fact that on iOS only secp256r1 is supported and on android
  /// all curves cann be supported be trusted execution environment but only secp256r1
  /// with strongbox (secure element).
  Future<String> generateKey(String curve, bool userAuthenticationRequired,
      [String? attestationChallenge]) {
    return OsKeystoreBackendPlatform.instance
        .generateKey(curve, userAuthenticationRequired, attestationChallenge);
  }

  /// Sign the given [data] with the key identified by [keyId]
  ///
  /// The returned signature is a plain signature (for ecdsa this means the concatenation of r and s value) as required be json web signatures for example.
  ///
  /// [promptData] is used to customize the System prompt for biometric authentication, when a key with userAuthenticationRequired=true is used.
  /// Android only, because on iOS the prompt cant be customized.
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
  /// This metadata has jwk format. The keys kty, key_ops, crv, x5c (to provide the public key on Android) or x and y on iOS,
  /// userAuthenticationRequired and securityLevel (API-Level 31 and above) or insideSecureHardware (Android API-Level below 31 and iOS) are used
  Future<Map> getKeyInfo(String keyId) {
    return OsKeystoreBackendPlatform.instance.getKeyInfo(keyId);
  }

  /// Returns whether the KeyStore controls the key identified by [keyId].
  Future<bool> hasKey(String keyId) {
    return OsKeystoreBackendPlatform.instance.hasKey(keyId);
  }

  /// Deletes the key identified by [keyId].
  Future<bool> deleteKey(String keyId) {
    return OsKeystoreBackendPlatform.instance.deleteKey(keyId);
  }
}
