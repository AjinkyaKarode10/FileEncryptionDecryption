package com.mywork;

import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.openssl.PEMWriter;


public class ReconFileEncrypt {

	public static void main(String[] args) throws Exception {
		
//		
//		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
//		keyGen.initialize(2048);
//		KeyPair keyPair = keyGen.generateKeyPair(); 
//		StringWriter stringWriter = new StringWriter();
//		StringWriter stringWriter1 = new StringWriter();
//		PEMWriter pemWriter = new PEMWriter(stringWriter);  
//		pemWriter.writeObject( keyPair.getPrivate());
//		pemWriter.close();
//		PEMWriter pemWriter1 = new PEMWriter(stringWriter1);  
//		pemWriter1.writeObject( keyPair.getPublic());
//		pemWriter1.close();
//		System.out.println("privatekey :: "+stringWriter.toString());
//		System.out.println("public key :: "+stringWriter1.toString());
		
		//step1 -> hash of original file
		String hashOfOriginalFile = FileReadeAndHashCompute.computeMessageDigestSHA256HashfromDataFile("/home/ajinkyakarode/Documents/Ajinkya/ReconTest.txt");
		System.out.println(hashOfOriginalFile);
		
		
		//step2 -> generate aes key and IV
		SecretKey randomAESKEY = Encryption.generateRandomAESKey();
		byte[] IV = Encryption.generateRandomIV();
		
		
		//step3 -> read private key and encrypt the hash generated in step1//privKeyNew.pem
		PrivateKey privateKey = Encryption.readRSAPrivateKeyPEM("/home/ajinkyakarode/Documents/Ajinkya/SBI/reconFileEncrypt/privateNew.pem");
		String encryptedHash = Encryption.encryptWithRSAPrivateKey(hashOfOriginalFile, privateKey);
		
		
		//step4 -> encrypt aeskey | IV with destnation pubkey
		String encodedPrivateKey = Base64.encodeBase64String(randomAESKEY.getEncoded());
		String encodedIV = Base64.encodeBase64String(IV);
		String keyivString = encodedPrivateKey + "|" + encodedIV;
		PublicKey destinationPubKey = Encryption.readRSAPublicKeyfromCert("/home/ajinkyakarode/Documents/Ajinkya/SBI/reconFileEncrypt/public.cer");
		String encryptedKeyIV = Encryption.encryptWithRSAPublicKey(keyivString, destinationPubKey);
		
		//step5 --> encrypt the original file with aes key and IV
		boolean isFileEncrypted = Encryption.processFileAESEncryptBase64("/home/ajinkyakarode/Documents/Ajinkya/ReconTest.txt", "/home/ajinkyakarode/Documents/Ajinkya/SBI/reconFileEncrypt/ReconTestEnc.txt", randomAESKEY, IV);
		
		//step6 write encryptedHash in 1st line and encryptedKeyIV in 2nd line
		System.out.println("encryptedHash : "+encryptedHash);
		System.out.println("encryptedKeyIV :"+encryptedKeyIV);
		
	}
	
}
