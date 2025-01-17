import 'dart:io' show Platform;
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:os_keystore_backend/os_keystore_backend.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('Generate key with second argument false', (tester) async {
    if (Platform.isAndroid){
      final keyId = await OsKeystoreBackend().generateKey("secp256r1", false);
      expect(keyId, isNotEmpty);
    }
    if(Platform.isIOS){
      try {
        // Call your plugin method in a way that triggers an argument error
        await OsKeystoreBackend().generateKey("secp256r1", false); // or invalid input
        fail('On iOS generateKey with false as second argument should throw an ArgumentError');
      } on PlatformException catch (e) {
        // Verify the error code and message
        expect(e.code, equals('generateKey.argumentError'));
        // Test e.message as well
        expect(e.message, isNotNull);
      }
    }
  });

  testWidgets('Generate key with second argument true', (tester) async {
    final keyId = await OsKeystoreBackend().generateKey("secp256r1", true);
    expect(keyId, isNotEmpty);
  });

  testWidgets('Sign and verify', (tester) async {
    final keyId = await OsKeystoreBackend().generateKey("secp256r1", true);
    final data = Uint8List.fromList([1, 2, 3, 4, 5]);
    final signature = await OsKeystoreBackend().sign(keyId, data);
    final verified = await OsKeystoreBackend().verify(keyId, data, signature);
    expect(verified, isTrue);
  });

  testWidgets('Get key info', (tester) async {
    final keyId = await OsKeystoreBackend().generateKey("secp256r1", true);
    final keyInfo = await OsKeystoreBackend().getKeyInfo(keyId);
    // TODO: Add more specific checks
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
