# AndroidArmour

We have include the following 2 Social Media Android app security features in this respository :
- [End-To-End Encryption](#section-1)  - 
- [Transaction Encryption](#section-2)

# <a name="section-1">
## 1. End-To-End Encryption :

### 1. **Generate RSA Key Pair for Key Exchange**
   - Each device needs a public-private key pair to exchange the AES encryption key securely.

```kotlin
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore

fun generateRSAKeyPair() {
    val keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
    keyPairGenerator.initialize(
        KeyGenParameterSpec.Builder(
            "communicationKeyAlias",
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        ).setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
         .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
         .build()
    )
    keyPairGenerator.generateKeyPair()
}
```

### 2. **Exchange the AES Key Securely**
   - The **AES key** is generated on the sender’s side and encrypted using the recipient’s **RSA public key** before being transmitted.

```kotlin
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.Cipher
import java.security.PublicKey

fun generateAESKey(): SecretKey {
    val keyGenerator = KeyGenerator.getInstance("AES")
    keyGenerator.init(256) // AES 256-bit encryption
    return keyGenerator.generateKey()
}

fun encryptAESKeyWithRSA(aesKey: SecretKey, recipientPublicKey: PublicKey): ByteArray {
    val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, recipientPublicKey)
    return cipher.doFinal(aesKey.encoded)  // Encrypt the AES key with RSA
}
```

### 3. **Encrypt and Decrypt Communication Data Using AES**

#### **Encrypt Data with AES**
```kotlin
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

fun encryptCommunicationData(data: String, aesKey: SecretKey): ByteArray {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, aesKey)
    val iv = cipher.iv  // Initialization Vector
    return cipher.doFinal(data.toByteArray())
}
```

#### **Decrypt Data with AES**
```kotlin
fun decryptCommunicationData(encryptedData: ByteArray, aesKey: SecretKey, iv: ByteArray): String {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val spec = GCMParameterSpec(128, iv)
    cipher.init(Cipher.DECRYPT_MODE, aesKey, spec)
    return String(cipher.doFinal(encryptedData))
}
```

### 4. **Store RSA Private Key Securely in Keystore**
   - Use the **Android Keystore** to store the RSA private key securely and decrypt the AES key on the recipient side.

```kotlin
fun getPrivateKey(): PrivateKey {
    val keyStore = KeyStore.getInstance("AndroidKeyStore")
    keyStore.load(null)
    return keyStore.getKey("communicationKeyAlias", null) as PrivateKey
}
```

### Steps Summary:
1. **RSA key pair** is generated for each device to securely exchange the AES key.
2. **AES key** is used to encrypt the communication data.
3. The AES key is **encrypted with the recipient’s RSA public key** for secure transmission.
4. **Decryption** happens on the recipient side using the AES key after it's securely received.
</a>

# <a name="section-2">
## 2. Account Hijacking Prevention:

### 1. **Two-Factor Authentication (2FA)**

#### **Step 1: Implement 2FA via OTP (One-Time Password)**
   - Send a **one-time password (OTP)** via SMS or email to the user's registered phone number or email for additional verification during login.

##### **Using Firebase for OTP Verification (SMS)**

1. **Add Firebase to your project** and set up **Firebase Authentication**.
2. Use the following code to send an OTP and verify it.

```kotlin
// Send OTP
fun sendOTP(phoneNumber: String) {
    val options = PhoneAuthOptions.newBuilder(FirebaseAuth.getInstance())
        .setPhoneNumber(phoneNumber)       // Phone number to send OTP to
        .setTimeout(60L, TimeUnit.SECONDS) // Timeout duration
        .setActivity(this)                 // Activity for callback
        .setCallbacks(callbacks)           // OnVerificationStateChangedCallbacks
        .build()
    PhoneAuthProvider.verifyPhoneNumber(options)
}

// Callback to handle OTP
val callbacks = object : PhoneAuthProvider.OnVerificationStateChangedCallbacks() {
    override fun onVerificationCompleted(credential: PhoneAuthCredential) {
        signInWithPhoneAuthCredential(credential)
    }

    override fun onVerificationFailed(e: FirebaseException) {
        // Handle failure
    }

    override fun onCodeSent(verificationId: String, token: PhoneAuthProvider.ForceResendingToken) {
        // Save verificationId and resending token for further verification
    }
}

// Verify OTP and Sign-in
fun verifyOTP(verificationId: String, code: String) {
    val credential = PhoneAuthProvider.getCredential(verificationId, code)
    signInWithPhoneAuthCredential(credential)
}

fun signInWithPhoneAuthCredential(credential: PhoneAuthCredential) {
    FirebaseAuth.getInstance().signInWithCredential(credential)
        .addOnCompleteListener { task ->
            if (task.isSuccessful) {
                // Successfully signed in
            } else {
                // Sign-in failed
            }
        }
}
```

#### **Step 2: 2FA Using TOTP (Time-based One-Time Password)**
   - Alternatively, implement **TOTP** using libraries like **Google Authenticator**.

   - Add the user’s account to a TOTP app (like Google Authenticator) and have the app generate a one-time password based on the current timestamp. The backend can then verify the TOTP.

### 2. **Unusual Login Monitoring**

#### **Step 1: Track Login Behavior**
   - Collect **user behavior data** such as IP address, location, and device information on each login. Use **Firebase Analytics** or a custom server to store this data.

```kotlin
fun trackLoginBehavior() {
    val ipAddress = getIPAddress()
    val deviceInfo = Build.MODEL
    val location = getCurrentLocation()

    // Store data for analysis
    logLoginEvent(ipAddress, deviceInfo, location)
}

fun getIPAddress(): String {
    // Use network libraries to get IP address
    return InetAddress.getLocalHost().hostAddress
}

fun getCurrentLocation(): Location? {
    // Use FusedLocationProviderClient for getting current location
    return fusedLocationClient.lastLocation
}
```

#### **Step 2: Analyze and Monitor for Unusual Activity**
   - On the server side, analyze the login data. If the login originates from a new location, IP address, or device, flag it as suspicious and prompt the user for additional verification (e.g., re-authentication via 2FA).

   - Send alerts if unusual login behavior is detected.

### Steps Summary:
1. **Implement 2FA**: Use OTP via SMS (Firebase) or TOTP (Google Authenticator).
2. **Track login behavior**: Log IP, location, and device info on each login.
3. **Monitor unusual logins**: Detect suspicious activity by comparing login patterns and prompt additional verification if needed.

These steps help prevent account hijacking by securing the login process and monitoring for unusual activities.
</a>
