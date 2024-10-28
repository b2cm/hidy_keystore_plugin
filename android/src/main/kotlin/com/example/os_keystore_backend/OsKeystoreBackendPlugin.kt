package com.example.os_keystore_backend

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.InvalidKeySpecException
import java.util.Base64
import kotlin.random.Random


/** OsKeystoreBackendPlugin */
class OsKeystoreBackendPlugin: FlutterPlugin, MethodCallHandler {
  /// The MethodChannel that will the communication between Flutter and native Android
  ///
  /// This local reference serves to register the plugin with the Flutter Engine and unregister it
  /// when the Flutter Engine is detached from the Activity
  private lateinit var channel : MethodChannel


  override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
    channel = MethodChannel(flutterPluginBinding.binaryMessenger, "os_keystore_backend")
    channel.setMethodCallHandler(this)
  }

  override fun onMethodCall(call: MethodCall, result: Result) {
    if (call.method == "getPlatformVersion") {
      result.success("Android ${android.os.Build.VERSION.RELEASE}")
    } else if(call.method == "generateKey"){
      val curve = call.argument<String>("curve")
      if(curve == null){
        result.error("ArgumentError", "Missing argument curve", "")
      }
      var userAuth  = call.argument<Boolean>("userAuthenticationRequired")
      if(userAuth == null) userAuth = false
      try {
        val keyId =  generateKey(curve!!, userAuth)
        result.success(keyId)
      } catch(e: Exception){
        result.error("GenerationError", e.message, "")
      }
    } else if(call.method == "sign"){
      val data = call.argument<ByteArray>("data")
      val keyId = call.argument<String>("keyId")

      if(keyId != null && data != null){
        try {
          val sig = sign(keyId, data)
          result.success(sig)
        }catch (e: Exception){
          result.error("VerificationError", e.message, "")
        }
      } else {
        result.error("ArgumentError", "Missing argument", "")
      }
    } else if(call.method == "verify"){
      val data = call.argument<ByteArray>("data")
      val signature = call.argument<ByteArray>("signature")
      val keyId = call.argument<String>("keyId")

      if(keyId != null && data != null && signature != null){
        try {
          val sig = verify(keyId, data, signature)
          result.success(sig)
        }catch (e: Exception){
          result.error("SigningError", e.message, "")
        }
      } else {
        result.error("ArgumentError", "Missing argument", "")
      }
    } else if(call.method == "getKeyInfo"){
      val keyId = call.argument<String>("keyId")

      if(keyId != null ){
        try {
          val sig = getKeyInfo(keyId)
          result.success(sig)
        }catch (e: Exception){
          result.error("SigningError", e.message, "")
        }
      } else {
        result.error("ArgumentError", "Missing argument", "")
      }
    }else if(call.method == "hasKey"){
      val keyId = call.argument<String>("keyId")

      if(keyId != null ){
        try {
          val sig = hasKey(keyId)
          result.success(sig)
        }catch (e: Exception){
          result.error("SigningError", e.message, "")
        }
      } else {
        result.error("ArgumentError", "Missing argument", "")
      }
    }else if(call.method == "deleteKey"){
      val keyId = call.argument<String>("keyId")

      if(keyId != null ){
        try {
          deleteKey(keyId)
          result.success(true)
        }catch (e: Exception){
          result.error("DeletionError", e.message, "")
        }
      } else {
        result.error("ArgumentError", "Missing argument", "")
      }
    }
    else {
      result.notImplemented()
    }
  }

  override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
    channel.setMethodCallHandler(null)
  }

  private fun generateKey(curve: String, userAuthenticationRequired: Boolean): String {
    val keyPairGenerator = KeyPairGenerator.getInstance(
      KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
    )

    val charPool : List<Char> = ('a'..'z') + ('A'..'Z') + ('0'..'9')
    var alias: String = (1..10)
      .map { Random.nextInt(0, charPool.size).let { charPool[it] } }
      .joinToString("")

    val digest: String = when(curve) {
      "secp256r1" -> KeyProperties.DIGEST_SHA256
      "secp384r1" -> KeyProperties.DIGEST_SHA384
      "secp521r1" -> KeyProperties.DIGEST_SHA512
      else -> {throw Exception("Unknown curve")}
    }

    alias = "${digest}_$alias"

    try {
      keyPairGenerator.initialize(
        KeyGenParameterSpec.Builder(
          alias,
          KeyProperties.PURPOSE_SIGN
        )
          .setAlgorithmParameterSpec(ECGenParameterSpec(curve))
          .setDigests(digest)
          .setIsStrongBoxBacked(true)
          .setUserAuthenticationRequired(userAuthenticationRequired)
          .build()
      )
    } catch (e: StrongBoxUnavailableException) {
      alias += "_tee"
      keyPairGenerator.initialize(
        KeyGenParameterSpec.Builder(
          alias,
          KeyProperties.PURPOSE_SIGN
        )
          .setAlgorithmParameterSpec(ECGenParameterSpec(curve))
          .setDigests(digest)
          .setUserAuthenticationRequired(true)

          .build()
      )
    }

    keyPairGenerator.generateKeyPair()

    return alias
  }

  private fun sign(keyId: String, data: ByteArray) : ByteArray {
    val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
      load(null)
    }

    val entry: KeyStore.Entry = ks.getEntry(keyId, null)
    if (entry !is KeyStore.PrivateKeyEntry) {
      throw  Exception("No private key")
    }

    val factory = KeyFactory.getInstance(entry.privateKey.algorithm, "AndroidKeyStore")
    val keyInfo: KeyInfo
    try {
      keyInfo = factory.getKeySpec(entry.privateKey, KeyInfo::class.java)
    } catch (e: InvalidKeySpecException) {
      throw  Exception("No keyInfo found")
    }

    var digest = keyInfo.digests.first().split("_").first()

    digest = digest.replace("-", "")

    val signature: ByteArray = Signature.getInstance("${digest}withECDSA").run {
      initSign(entry.privateKey)
      update(data)
      sign()
    }

    return signature
  }

  private fun verify(keyId: String, data: ByteArray, signature: ByteArray) : Boolean {
    val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
      load(null)
    }

    val entry: KeyStore.Entry = ks.getEntry(keyId, null)
    if (entry !is KeyStore.PrivateKeyEntry) {
      throw  Exception("No private key")
    }

    val factory = KeyFactory.getInstance(entry.privateKey.algorithm, "AndroidKeyStore")
    val keyInfo: KeyInfo
    try {
      keyInfo = factory.getKeySpec(entry.privateKey, KeyInfo::class.java)
    } catch (e: InvalidKeySpecException) {
      throw  Exception("No keyInfo found")
    }

    var digest = keyInfo.digests.first().split("_").first()

    digest = digest.replace("-", "")

    val verified: Boolean = Signature.getInstance("${digest}withECDSA").run {
      initVerify(entry.certificate)
      update(data)
      verify(signature)
    }

    return verified
  }

  private fun getKeyInfo(keyId: String) : Map<String, Any>{
    val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
      load(null)
    }

    val entry: KeyStore.Entry = ks.getEntry(keyId, null)
    if (entry !is KeyStore.PrivateKeyEntry) {
      throw  Exception("No private key")
    }

    val factory = KeyFactory.getInstance(entry.privateKey.algorithm, "AndroidKeyStore")
    val keyInfo: KeyInfo
    try {
      keyInfo = factory.getKeySpec(entry.privateKey, KeyInfo::class.java)
    } catch (e: InvalidKeySpecException) {
      throw  Exception("No keyInfo found")
    }


    val data = LinkedHashMap<String, Any>()
    //val x5c = ArrayList<String>()
    //x5c.add(Base64.getEncoder().encodeToString(entry.certificate.encoded))
    val x5c = entry.certificateChain.map { c -> Base64.getEncoder().encodeToString(c.encoded) }
    data["x5c"] = x5c
    data["kty"] = "EC"

    val keyOps = ArrayList<String>()
    var keyP = keyInfo.purposes
    if(keyP == 128){
      // no other purpose possible
      keyOps.add("attestKey")
    } else {
      if(keyP / 64 == 1 ){
        keyOps.add("deriveKey")
        keyP %= 64
      }
      if(keyP / 32 == 1){
        keyOps.add("wrapKey")
        keyP %= 32
      }
      if(keyP / 8 == 1){
        keyOps.add("verify")
        keyP %= 8
      }
      if(keyP / 4 == 1){
        keyOps.add("sign")
        keyP %= 4
      }
      if(keyP / 2 == 1){
        keyOps.add("decrypt")
        keyP %= 2
      }
      if(keyP == 1){
        keyOps.add("encrypt")
      }
    }
    data["key_ops"] = keyOps
    data["userAuthenticationRequired"] = keyInfo.isUserAuthenticationRequired

    if(android.os.Build.VERSION.SDK_INT >= 31 ){
      data["securityLevel"] = keyInfo.securityLevel
    }else{
      data["isInsideSecureHardware"] = keyInfo.isInsideSecureHardware
    }

    return data
  }

  private fun hasKey(keyId: String): Boolean{
    val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
      load(null)
    }
    return ks.isKeyEntry(keyId)
  }

  private fun deleteKey(keyId: String){
    val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
      load(null)
    }
    ks.deleteEntry(keyId)
  }
}
