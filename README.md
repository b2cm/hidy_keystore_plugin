# os_keystore_backend

This Plugin makes Android KeyStore and iOS SecureEnclave usable for Flutter Apps.
For now generating new keys and using them for signing data ist supported.

## Getting Started
Generate a key and use it for signing: 
```
final _osKeystoreBackendPlugin = OsKeystoreBackend();
var keyId = await _osKeystoreBackendPlugin.generateKey('secp256r1', true);
var sig = await _osKeystoreBackendPlugin.sign(
          keyId,
          ascii.encode('abcdefg'));

```

For more complex example please have a look at [example](./example).

## Notes
- On Android the plugin tries to use Strongbox first (only possible with curve secp256r1)
if not available the trusted execution environment is used
- On iOS only curve secp256r1 is supported
