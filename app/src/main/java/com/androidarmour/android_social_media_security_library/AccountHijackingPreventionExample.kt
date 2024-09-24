package com.androidarmour.android_social_media_security_library

import android.app.Activity
import android.content.Context
import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.google.firebase.FirebaseException
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.auth.PhoneAuthCredential
import com.google.firebase.auth.PhoneAuthOptions
import com.google.firebase.auth.PhoneAuthProvider
import java.util.concurrent.TimeUnit

class AccountHijackingPreventionExample : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_account_hijacking_prevention_example)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }
    }
}

// Send OTP
fun sendOTP(phoneNumber: String, context : Activity) {
    val options = PhoneAuthOptions.newBuilder(FirebaseAuth.getInstance())
        .setPhoneNumber(phoneNumber)       // Phone number to send OTP to
        .setTimeout(60L, TimeUnit.SECONDS) // Timeout duration
        .setActivity(context)                 // Activity for callback
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