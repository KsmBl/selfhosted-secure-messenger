package org.selfhosted.securemessenger

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * 32-byte secret bound to this device's Android Keystore (ADR-0005).
 *
 * The secret is random and stored encrypted with a non-exportable AES key in
 * the Keystore (StrongBox when available). It is mixed into the key
 * derivation of the pattern-protected container, so a copied container
 * cannot be brute-forced on another machine.
 */
object HardwareSecret {
    private const val ALIAS = "ssm_container_binding"
    private const val FILE = "hw_secret.bin"
    private const val IV_LENGTH = 12

    private fun keyStore(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun createKey(context: Context): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setIsStrongBoxBacked(strongBox)
            .build()
        val hasStrongBox = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        return try {
            generator.init(spec(hasStrongBox))
            generator.generateKey()
        } catch (e: StrongBoxUnavailableException) {
            generator.init(spec(false))
            generator.generateKey()
        }
    }

    /** Creates the secret on first use; afterwards decrypts the stored one. */
    fun get(context: Context): ByteArray {
        val file = File(context.noBackupFilesDir, FILE)
        val store = keyStore()
        if (!file.exists()) {
            val key = (store.getKey(ALIAS, null) as? SecretKey) ?: createKey(context)
            val secret = ByteArray(32).also { SecureRandom().nextBytes(it) }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val encrypted = cipher.iv + cipher.doFinal(secret)
            val tmp = File(file.parentFile, "$FILE.tmp")
            tmp.writeBytes(encrypted)
            tmp.renameTo(file)
            return secret
        }
        val key = store.getKey(ALIAS, null) as SecretKey
        val data = file.readBytes()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, data, 0, IV_LENGTH))
        return cipher.doFinal(data, IV_LENGTH, data.size - IV_LENGTH)
    }
}
