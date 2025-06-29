package com.example.spring_security.spring_secuirty;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

@SpringBootApplication
public class SpringSecuirtyApplication {

	public static void main(String[] args) throws Exception {
		SpringApplication.run(SpringSecuirtyApplication.class, args);
		System.out.println("Working..");

		CryptoService cryptoService = new CryptoService();
		SecretKey aesKey = cryptoService.generateAESKey();
//		System.out.println("aesKey -> " + aesKey);

		String plaintext = "{\"userId\":\"USR123456\",\"fullName\":\"Pankaj Singh\",\"email\":\"pankaj@example.com\",\"phone\":\"+91-9876543210\",\"dob\":\"1998-06-15\",\"address\":{\"street\":\"A-123, Sector 21\",\"city\":\"Faridabad\",\"state\":\"Haryana\",\"postalCode\":\"121001\"},\"preferences\":{\"newsletter\":true,\"notifications\":{\"email\":true,\"sms\":false},\"language\":\"en-IN\"},\"medicalHistory\":[{\"type\":\"allergy\",\"details\":\"Pollen allergy\",\"lastChecked\":\"2023-12-10\"},{\"type\":\"surgery\",\"details\":\"Appendectomy\",\"lastChecked\":\"2021-04-20\"}],\"createdAt\":\"2024-07-01T10:30:00Z\"}";

		String encryptedText = cryptoService.encryptTextWithAES(plaintext, aesKey);

		System.out.println("encryptedText -> " + encryptedText);

		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);
		KeyPair pair = generator.generateKeyPair();


		PrivateKey privateKey = pair.getPrivate();
		PublicKey publicKey = pair.getPublic();

		String base64PublicKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
		String base64PrivateKey = Base64.getEncoder().encodeToString(privateKey.getEncoded());

		System.out.println("base64PublicKey: " + base64PublicKey);
		System.out.println("private key " + base64PrivateKey);

//		String clientPublicKeyBase64 = "abc";
		// 3. Encrypt AES key using client's RSA public key
		String encryptedAESKey = cryptoService.encryptAESKeyWithRSA(aesKey, base64PublicKey,"pankaj");

		// 4. Optional: log Base64 AES key (for debugging only, never send raw key)
		String base64AESKey = cryptoService.getBase64AESKey(aesKey);

		System.out.println("encryptedAESKey -> " + encryptedAESKey);


		SecretKey receivedAESKey = cryptoService.decryptAESKeyWithRSA(encryptedAESKey,base64PrivateKey);
		String base64Key = Base64.getEncoder().encodeToString(receivedAESKey.getEncoded());
		System.out.println("Received AES Key is: " + base64Key);
		String decodedMessage =  cryptoService.decryptTextWithAES(encryptedText,receivedAESKey);
		System.out.println("Decoded message is  " + decodedMessage);
	}

}
