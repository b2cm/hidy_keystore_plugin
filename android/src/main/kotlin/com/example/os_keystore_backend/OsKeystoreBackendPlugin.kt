package com.example.os_keystore_backend

import android.app.Activity
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import com.hierynomus.asn1.ASN1InputStream
import com.hierynomus.asn1.ASN1OutputStream
import com.hierynomus.asn1.encodingrules.der.DERDecoder
import com.hierynomus.asn1.encodingrules.der.DEREncoder
import com.hierynomus.asn1.types.constructed.ASN1Sequence
import com.hierynomus.asn1.types.primitive.ASN1Integer
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.InvalidAlgorithmParameterException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.InvalidKeySpecException
import java.util.Base64
import java.util.concurrent.Executor
import kotlin.random.Random


/** OsKeystoreBackendPlugin */
class OsKeystoreBackendPlugin: FlutterPlugin, MethodCallHandler, ActivityAware {
  /// The MethodChannel that will the communication between Flutter and native Android
  ///
  /// This local reference serves to register the plugin with the Flutter Engine and unregister it
  /// when the Flutter Engine is detached from the Activity
  private lateinit var channel : MethodChannel
  private var activity: Activity? = null


  override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
    channel = MethodChannel(flutterPluginBinding.binaryMessenger, "os_keystore_backend")
    channel.setMethodCallHandler(this)
  }


  class UiThreadExecutor : Executor {
    private val handler: Handler = Handler(Looper.getMainLooper())

    override fun execute(command: Runnable) {
      handler.post(command)
    }
  }

  override fun onMethodCall(call: MethodCall, result: Result) {
    if (call.method == "getPlatformVersion") {
      result.success("Android ${android.os.Build.VERSION.RELEASE}")
    } else if(call.method == "generateKey"){
      val curve = call.argument<String>("curve")
      if(curve == null){
        result.error("ArgumentError", "Missing argument curve", "")
      }

      val userAuth = call.argument<Boolean>("userAuthenticationRequired") ?: false
      val attestationChallenge = call.argument<String>("attestationChallenge") ?: ""

      try {
        val keyId = generateKey(curve!!, userAuth, attestationChallenge)
        result.success(keyId)
      } catch(e: Exception){
        result.error("GenerationError", e.message, e.stackTraceToString())
      }
    } else if(call.method == "sign"){
      val data = call.argument<ByteArray>("data")
      val keyId = call.argument<String>("keyId")

      if(keyId != null && data != null){
        try {
          sign(keyId,
            data,
            result,
            call.argument<String?>("biometricPromptTitle"),
            call.argument<String?>("biometricPromptSubtitle"),
            call.argument<String?>("biometricPromptNegative"))
        }catch (e: Exception){
          result.error("SigningError", e.message, "")
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
          result.error("VerificationError", e.message, "")
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

  private fun generateKey(curve: String, userAuthenticationRequired: Boolean, attestationChallenge: String): String {
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
          .setAttestationChallenge(attestationChallenge.toByteArray())
          .build()
      )
      keyPairGenerator.generateKeyPair()
    } catch (e: StrongBoxUnavailableException) {
      alias += "_tee"
     val builder = KeyGenParameterSpec.Builder(
       alias,
       KeyProperties.PURPOSE_SIGN
     )
       .setAlgorithmParameterSpec(ECGenParameterSpec(curve))
       .setDigests(digest)
       .setUserAuthenticationRequired(userAuthenticationRequired)
       .setAttestationChallenge(attestationChallenge.toByteArray())
      val r =  builder.build()
      keyPairGenerator.initialize(r)
      keyPairGenerator.generateKeyPair()
    } catch(e: InvalidAlgorithmParameterException){
      alias += "_tee"
      val builder = KeyGenParameterSpec.Builder(
        alias,
        KeyProperties.PURPOSE_SIGN
      )
        .setAlgorithmParameterSpec(ECGenParameterSpec(curve))
        .setDigests(digest)
        .setUserAuthenticationRequired(userAuthenticationRequired)
        .setAttestationChallenge(attestationChallenge.toByteArray())
      val r =  builder.build()
      keyPairGenerator.initialize(r)
      keyPairGenerator.generateKeyPair()
    }

    return alias
  }

  private fun sign(keyId: String,
                   data: ByteArray,
                   result: Result,
                   biometricPromptTitle: String?,
                   biometricPromptSubtitle: String?,
                   biometricPromptNegative: String?)  {
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
      result.error("SigningError", "No Key found", null)
      return
    }

    var digest = keyInfo.digests.first().split("_").first()

    digest = digest.replace("-", "")

    var size = 64
    if(digest == "SHA384"){
      size = 96
    }
    else if(digest == "SHA512"){
      size = 132
    }

    var signature: ByteArray

    if(keyInfo.isUserAuthenticationRequired){
      if(activity !is FragmentActivity){
        result.error("SigningError", "Not in Fragment Activity", "")
        return
      }

      val biometricPrompt = BiometricPrompt(activity as FragmentActivity, UiThreadExecutor(),
        object : BiometricPrompt.AuthenticationCallback() {
          override fun onAuthenticationError(errorCode: Int,
                                             errString: CharSequence) {
            super.onAuthenticationError(errorCode, errString)
            result.error("SigningError", "Authentication error", null)
          }

          override fun onAuthenticationSucceeded(
            biometricResult: BiometricPrompt.AuthenticationResult) {
            super.onAuthenticationSucceeded(biometricResult)
            signature = biometricResult.cryptoObject?.signature!!.sign()
            result.success(toP1363(signature, size))
          }

          override fun onAuthenticationFailed() {
            super.onAuthenticationFailed()
            result.error("SigningError", "Authentication failed", null)
          }
        })

      val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle(biometricPromptTitle ?: "Biometric login for signing")
        .setSubtitle(biometricPromptSubtitle ?: "Please Authenticate for the usage of your signing key")
        .setNegativeButtonText(biometricPromptNegative ?: "Cancel")
        .build()

      val s = Signature.getInstance("${digest}withECDSA")
      s.initSign(entry.privateKey)
      s.update(data)

      biometricPrompt.authenticate(promptInfo,
        BiometricPrompt.CryptoObject(s))

    } else {
      signature = Signature.getInstance("${digest}withECDSA").run {
        initSign(entry.privateKey)
        update(data)
        sign()
      }
      result.success(toP1363(signature, size))
    }


  }

  // source: https://stackoverflow.com/questions/77653037/signing-jwt-using-es256-on-android
 private fun toP1363(derSignature: ByteArray, size: Int) : ByteArray {
    val stream = ASN1InputStream(DERDecoder(), derSignature)
    val sequence = stream.readObject<ASN1Sequence>()
    val r = (sequence.get(0).value as BigInteger).toString(16).padStart(size, '0')
    val s = (sequence.get(1).value as BigInteger).toString(16).padStart(size, '0')
    return (r + s).hexStringToByteArray()
  }

  private fun String.hexStringToByteArray() = this.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

  private fun toASN1(plainSignature: ByteArray) : ByteArray{
    val h = plainSignature.size / 2
    val r = plainSignature.copyOfRange(0, h)
    val s = plainSignature.copyOfRange(h, plainSignature.size)
    val ri = BigInteger(1,r)
    val si = BigInteger(1,s)
    val seq = ASN1Sequence(listOf(ASN1Integer(ri),ASN1Integer(si)))

    val baos = ByteArrayOutputStream()
    val out = ASN1OutputStream(DEREncoder(), baos)

    out.writeObject(seq)

    return baos.toByteArray()
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

    println(toASN1(signature).joinToString(prefix = "[", postfix = "]"))

    val verified: Boolean = Signature.getInstance("${digest}withECDSA").run {
      initVerify(entry.certificate)
      update(data)
      verify(toASN1(signature))
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

  override fun onAttachedToActivity(binding: ActivityPluginBinding) {
    activity = binding.activity
  }

  override fun onDetachedFromActivityForConfigChanges() {
    activity = null
  }

  override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
    activity = binding.activity
  }

  override fun onDetachedFromActivity() {
    activity = null
  }
}
