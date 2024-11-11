import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:os_keystore_backend/os_keystore_backend.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  String keyId = 'Not generated';
  bool keyGenerated = false;
  String signature = 'Nothing signed';
  String verifiedG = 'Nothing verified';
  final _osKeystoreBackendPlugin = OsKeystoreBackend();

  @override
  void initState() {
    super.initState();
  }

  Future<void> generateKey() async {
    setState(() {
      keyId = 'Generating';
    });

    try {
      keyId = await _osKeystoreBackendPlugin.generateKey('secp384r1', false);
      keyGenerated = true;
    } on PlatformException catch (e) {
      print(e);
      keyId = 'Failed to generate key';
    }

    setState(() {});
  }

  Future<void> sign() async {
    setState(() {
      signature = 'signing';
    });

    Uint8List? sig;
    try {
      sig = await _osKeystoreBackendPlugin.sign(keyId, ascii.encode('abcdefg'));
    } on PlatformException catch (e) {
      print(e);
      signature = 'Failed to sign';
    }

    setState(() {
      if (sig != null) {
        signature = base64Encode(sig);
      }
    });
  }

  Future<void> verify() async {
    setState(() {
      verifiedG = 'verification';
    });

    bool? verified;
    try {
      verified = await _osKeystoreBackendPlugin.verify(
          keyId, ascii.encode('abcdefg'), base64Decode(signature));
    } on PlatformException catch (e) {
      print(e);
      signature = 'Failed to sign';
    }

    setState(() {
      if (verified != null) {
        verifiedG = 'Result: $verified';
      }
    });
  }

  Future<void> getKeyInfo() async {
    try {
      var info = await _osKeystoreBackendPlugin.getKeyInfo(
        keyId,
      );
      var x5c = info['x5c'] as List;
      for (var entry in x5c) {
        print(entry);
      }
      print(info);
    } on PlatformException catch (e) {
      print(e);
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Plugin example app'),
        ),
        body: Center(
          child: Column(children: [
            ElevatedButton(onPressed: generateKey, child: Text('Generate Key')),
            SizedBox(
              height: 10,
            ),
            Text(
              keyId,
            ),
            SizedBox(
              height: 10,
            ),
            ElevatedButton(onPressed: sign, child: Text('Sign')),
            SizedBox(
              height: 10,
            ),
            Text(
              signature,
            ),
            ElevatedButton(onPressed: verify, child: Text('Verify')),
            SizedBox(
              height: 10,
            ),
            Text(
              verifiedG,
            ),
            SizedBox(
              height: 10,
            ),
            ElevatedButton(onPressed: getKeyInfo, child: Text('Info')),
          ]),
        ),
      ),
    );
  }
}
