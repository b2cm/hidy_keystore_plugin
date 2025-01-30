import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:os_keystore_backend/os_keystore_backend.dart';
import 'package:sd_jwt/sd_jwt.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('Generate key secp256r1', (tester) async {
    final keyId = await OsKeystoreBackend().generateKey("secp256r1", true);
    expect(keyId, isNotEmpty);
  });

  testWidgets('Sign and verify', (tester) async {
    final keyId = await OsKeystoreBackend().generateKey("secp256r1", true);
    final data = Uint8List.fromList([1, 2, 3, 4, 5]);
    final signature = await OsKeystoreBackend().sign(keyId, data);
    final verified = await OsKeystoreBackend().verify(keyId, data, signature);
    expect(verified, isTrue);
    final falseData = Uint8List.fromList([1, 2, 3, 4, 6]);
    final verified2 =
        await OsKeystoreBackend().verify(keyId, falseData, signature);
    expect(verified2, isFalse);
  });

  testWidgets('Sign and Verify with jws', (tester) async {
    var jwt = Jwt(additionalClaims: {'test': 'Test'}, issuedAt: DateTime.now());
    final keyId = await OsKeystoreBackend().generateKey("secp256r1", true);
    var jws = await jwt.sign(
        signer: KeyStoreCryptoProvider(keyId),
        header: JwsJoseHeader(
            algorithm: SigningAlgorithm.ecdsaSha256Prime, type: 'test'));

    var publicKeyData = await OsKeystoreBackend().getKeyInfo(keyId);

    Jwk jwk;
    if (publicKeyData.containsKey('x5c') &&
        (publicKeyData['x5c'] as List).isNotEmpty) {
      jwk = Jwk.fromCertificate((publicKeyData['x5c'] as List).first);
    } else {
      jwk = Jwk.fromJson(publicKeyData.map((k, v) => MapEntry(k as String, v)));
    }

    var verified =
        jws.verify(PointyCastleCryptoProvider(jwk.key as AsymmetricKey?));
    expect(verified, isTrue);
  });

  testWidgets('Get key info', (tester) async {
    final keyId = await OsKeystoreBackend().generateKey("secp256r1", true);
    final keyInfo = await OsKeystoreBackend().getKeyInfo(keyId);
    expect(keyInfo, isNotNull);
  });

  testWidgets('Has key', (tester) async {
    final keyId = await OsKeystoreBackend().generateKey("secp256r1", true);
    final hasKey = await OsKeystoreBackend().hasKey(keyId);
    expect(hasKey, isTrue);
  });

  testWidgets('Delete key', (tester) async {
    final keyId = await OsKeystoreBackend().generateKey("secp256r1", true);
    final deleted = await OsKeystoreBackend().deleteKey(keyId);
    expect(deleted, isTrue);
    try {
      final hasKey = await OsKeystoreBackend().hasKey(keyId);
      fail('Key should be deleted');
    } on PlatformException catch (e) {
      // Verify the error code and message
      expect(e.code, equals('hasKey.keyNotFound'));
    }
  });
}

class KeyStoreCryptoProvider extends CryptoProvider {
  String keyId;

  KeyStoreCryptoProvider(this.keyId);
  @override
  Uint8List digest(
      {required Uint8List data, required DigestAlgorithm algorithm}) {
    // TODO: implement digest
    throw UnimplementedError();
  }

  @override
  Key generateKeyPair({required KeyParameters keyParameters}) {
    // TODO: implement generateKeyPair
    throw UnimplementedError();
  }

  @override
  FutureOr<Signature> sign(
      {required Uint8List data, required SigningAlgorithm algorithm}) async {
    var sig = await OsKeystoreBackend().sign(keyId, data);
    return Signature.fromSignatureBytes(sig, algorithm);
  }

  @override
  FutureOr<bool> verify(
      {required Uint8List data,
      required SigningAlgorithm algorithm,
      required Signature signature}) {
    // TODO: implement verify
    throw UnimplementedError();
  }
}
