package com.encryption;

import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Application {

	private static final String ENCRYPTION_CIPHER_ALGORITHM_MODE_AND_PADDING = "AES/CBC/PKCS5Padding";

	private String secretKey = "AESEncryptionKey";

	public String encrypt(String plainText, String salt) {
		try {
			Cipher cipher = Cipher.getInstance(ENCRYPTION_CIPHER_ALGORITHM_MODE_AND_PADDING);
			byte[] initVector = getIVParameter();
			cipher.init(Cipher.ENCRYPT_MODE, getSecretKeySpec(salt), new IvParameterSpec(initVector));
			byte[] encrypted = cipher.doFinal((plainText + "|" + salt).getBytes());
			StringBuilder cipherText = new StringBuilder();
			cipherText.append(Base64.getEncoder().encodeToString(initVector));
			cipherText.append(":");
			cipherText.append(Base64.getEncoder().encodeToString(encrypted));
			return cipherText.toString();
		} catch (Exception exception) {
			System.out.println(exception.toString());
		}
		return null;
	}
	
	public String decrypt(String cipherText, String salt) {
		try {
			Cipher cipher = Cipher.getInstance(ENCRYPTION_CIPHER_ALGORITHM_MODE_AND_PADDING);
			String[] parts = cipherText.split(":");
			cipher.init(Cipher.DECRYPT_MODE, getSecretKeySpec(salt), new IvParameterSpec(Base64.getDecoder().decode(parts[0])));
			byte[] original = cipher.doFinal(Base64.getDecoder().decode(parts[1]));
			return new String(original).replace("|" +salt, "");
			
		}catch (Exception exception) {
			System.out.println(exception.toString());
		}
		return null;
	}

	private byte[] getIVParameter() {
		byte[] initVector = new byte[16];
		SecureRandom random = new SecureRandom();
		random.nextBytes(initVector);
		return initVector;
	}

	private Key getSecretKeySpec(String salt)
			throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException {
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		KeySpec keySpec = new PBEKeySpec(secretKey.toCharArray(), salt.getBytes("UTF-8"), 65536, 128);
		SecretKey tempSecretKey = keyFactory.generateSecret(keySpec);
		return new SecretKeySpec(tempSecretKey.getEncoded(), "AES");

	}
	
	public static void main( String[] args )
    {
    	
    	String originalString = "dogBlueTest";
    	String salt = "=2psferfweknjfhwejq69";
    	Application app = new Application();
    	String encryptedString = app.encrypt(originalString, salt) ;
    	String decryptedString = app.decrypt(encryptedString, salt) ;
    	
    	System.out.println(originalString);
    	System.out.println(encryptedString);
    	System.out.println(decryptedString);
    }
}
