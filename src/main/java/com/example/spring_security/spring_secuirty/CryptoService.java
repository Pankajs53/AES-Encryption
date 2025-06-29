package com.example.spring_security.spring_secuirty;

import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Arrays;

@Service
public class CryptoService {

    // 1. Generate AES-128 Key
    public SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // 128-bit key
        return keyGen.generateKey();
    }

    // 2. Encrypt AES key with RSA Public Key (Base64 input)
    // 2. Encrypt AES key with RSA Public Key (Base64 input) with partner_id prefix
    public String encryptAESKeyWithRSA(SecretKey aesKey, String base64PublicKey, String partnerId) throws Exception {
        // Step 1: Get AES key in base64 format
        String base64AESKey = Base64.getEncoder().encodeToString(aesKey.getEncoded());

        // Step 2: Concatenate partner_id and AES key with ";;"
        String finalPayload = partnerId + ";;" + base64AESKey;
        System.out.println("Final Payload is: "+ finalPayload);

        // Step 3: Convert to bytes
        byte[] payloadBytes = finalPayload.getBytes();

        // Step 4: Load public key from base64
        byte[] publicKeyBytes = Base64.getDecoder().decode(base64PublicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        // Step 5: Encrypt the finalPayload using RSA
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedPayload = rsaCipher.doFinal(payloadBytes);

        // Step 6: Return encrypted payload as base64
        return Base64.getEncoder().encodeToString(encryptedPayload);
    }


    // 🔓 NEW: Decrypt AES key using RSA Private Key (Base64 input)
    public SecretKey decryptAESKeyWithRSA(String encryptedAESKeyBase64, String base64PrivateKey) throws Exception {
        // Step 1: Decode encrypted AES key from Base64
        byte[] encryptedAESKeyBytes = Base64.getDecoder().decode(encryptedAESKeyBase64);
        byte[] privateKeyBytes = Base64.getDecoder().decode(base64PrivateKey);

        // Step 2: Load Private Key
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        // Step 3: Decrypt using RSA
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedPayloadBytes = rsaCipher.doFinal(encryptedAESKeyBytes);
        String decryptedPayload = new String(decryptedPayloadBytes);  // e.g., "pankaj;;zt1SJmVSFDQVpCF8zRcNUA=="

        System.out.println("hey + " + decryptedPayload);
        // Step 4: Split to extract partnerId and AES key
        String[] parts = decryptedPayload.split(";;");
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid decrypted format. Expected 'partner_id;;aes_key_base64'");
        }

        String partnerId = parts[0]; // Not used here, but you can log or validate it
        String base64AESKey = parts[1];

        // Step 5: Decode AES key from Base64
        byte[] aesKeyBytes = Base64.getDecoder().decode(base64AESKey);

        // Step 6: Rebuild SecretKey from bytes
        return new javax.crypto.spec.SecretKeySpec(aesKeyBytes, 0, aesKeyBytes.length, "AES");
    }

    // 3. Encrypt text using AES (with random IV) and return Base64(IV + ciphertext)
    public String encryptTextWithAES(String plainText, SecretKey aesKey) throws Exception {
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        // Generate random IV
        SecureRandom secureRandom = new SecureRandom();
        byte[] ivBytes = new byte[16];
        secureRandom.nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
        byte[] encryptedBytes = aesCipher.doFinal(plainText.getBytes());

        // Combine IV + ciphertext
        byte[] ivAndCiphertext = new byte[ivBytes.length + encryptedBytes.length];
        System.arraycopy(ivBytes, 0, ivAndCiphertext, 0, ivBytes.length);
        System.arraycopy(encryptedBytes, 0, ivAndCiphertext, ivBytes.length, encryptedBytes.length);

        return Base64.getEncoder().encodeToString(ivAndCiphertext);
    }

    // 4. Decrypt Base64(IV + ciphertext) using AES
    public String decryptTextWithAES(String base64Input, SecretKey aesKey) throws Exception {
        byte[] ivAndCiphertext = Base64.getDecoder().decode(base64Input);
        byte[] ivBytes = Arrays.copyOfRange(ivAndCiphertext, 0, 16);
        byte[] encryptedBytes = Arrays.copyOfRange(ivAndCiphertext, 16, ivAndCiphertext.length);

        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);

        byte[] decryptedBytes = aesCipher.doFinal(encryptedBytes);
        return new String(decryptedBytes);
    }

    // Utility: Get Base64 AES Key
    public String getBase64AESKey(SecretKey aesKey) {
        return Base64.getEncoder().encodeToString(aesKey.getEncoded());
    }
}
