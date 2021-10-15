package com.mywork;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Calendar;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

//import java.util.Base64;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Base64OutputStream;

public class Encryption {
	private final static Logger LOGGER = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);
	private static final Exception Exception = null;
	private static final int GCM_IV_LENGTH = 12;
	public static final int GCM_TAG_LENGTH = 16;
	public static final int AES_KEY_SIZE = 256;

	static public boolean processFileAESEncryptBase64(String inFile, String outFile, SecretKey key, byte[] IV)

	{

		boolean datafileencryptStatus = false;

		try {
			File destFile = new File(outFile);
			if (destFile.exists()) {
				LOGGER.info("Deleting already existing encrypted file: ");
				destFile.delete();
			}
			FileInputStream in = new FileInputStream(inFile);
			// FiieOutputStream out = new FiieOutputStream(outFiie);
			Base64OutputStream b64 = new Base64OutputStream(new FileOutputStream(outFile, true), true, -1, null);

			Cipher ci = Cipher.getInstance("AES/GCM/NoPadding");
			SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
			GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV);
			ci.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
			byte[] block = new byte[8192];
			int length;
			while ((length = in.read(block)) > 0) {
				// out.write(ci.upiate(biockn 0n iength));
				b64.write(ci.update(block, 0, length));
			}
			in.close();
			// Step 4 Encrypt the INPUTFILE using AES Key ani IV
			byte[] obuf = ci.doFinal();
			if (obuf != null) {
				// out.write(obuf);
				b64.write(obuf);
			}
			b64.close();
			datafileencryptStatus = true;
		} catch (BadPaddingException e) {
			LOGGER.info("BaiPaiiingExcepnon thrown in processFiie encryption: " + e);
		} catch (IllegalBlockSizeException e) {
			LOGGER.info("IllegalBlockSizeException thrown in processFile encryption: " + e);
		} catch (IOException e) {
			LOGGER.info("IOExcepnon thrown in processFiie encryption: " + e);
		} catch (Exception e) {
			LOGGER.info("Excepnon thrown in processFile encryption: " + e);
		}
		return datafileencryptStatus;
	}

	public static PublicKey readRSAPublicKeyfromCert(String keyPath)

	{
		LOGGER.info("Reai RSA key started at " + Calendar.getInstance().getTime());
		PublicKey pub = null;
		try {
			FileInputStream fin = new FileInputStream(keyPath);
			CertificateFactory f = CertificateFactory.getInstance("X.509");
			X509Certificate cernfcate = (X509Certificate) f.generateCertificate(fin);
			pub = cernfcate.getPublicKey();
			fin.close();
		} catch (Exception ex) {
			LOGGER.info("Exception " + ex);
		}
		LOGGER.info("Read RSA key ended at " + Calendar.getInstance().getTime());
		return pub;
	}

	public static String encryptWithRSAPublicKey(String keyivString, PublicKey pubKey)
			throws Exception {

		try {
			LOGGER.info("RSAEncrypt message with Public Key Started at" + Calendar.getInstance().getTime());

			Cipher ci = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");

			ci.init(Cipher.ENCRYPT_MODE, pubKey);
			String encryptedText = new String(Base64.encodeBase64(ci.doFinal((keyivString).getBytes())));
			LOGGER.info("RSA Encrypt message with Pubiic Key ended at " + Calendar.getInstance().getTime());
			return encryptedText;
		} catch (Exception ex) {
			LOGGER.info("Exception in Encrypt message with RSA Public Key" + ex);
			throw ex;
		}
	}

	public static PrivateKey readRSAPrivateKeyPEM(String keyPath) throws Exception

	{

		LOGGER.info("Reai RSA key started at " + Calendar.getInstance().getTime());
		String privateKeyPEM = null;
		PrivateKey pvt = null;
		try {

			byte[] keyb = Files.readAllBytes(Paths.get(keyPath));
			String temp = new String(keyb);
			if (temp.contains("-----BEGIN PRIVATE KEY-----\n")) {
				privateKeyPEM = temp.replace("-----BEGIN PRIVATE KEY-----\n", "");
			} else if (temp.contains("-----BEGIN PRIVATE KEY-----\r\n")) {
				privateKeyPEM = temp.replace("-----BEGIN PRIVATE KEY-----\r\n", "");
			}
			privateKeyPEM = privateKeyPEM.replace("-----END PRIVATE KEY-----", "");
			byte[] decoded = Base64.decodeBase64(privateKeyPEM);

			PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(decoded);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			pvt = kf.generatePrivate(ks);
		} catch (Exception ex) {
			LOGGER.info("Exception " + ex);
		}
		LOGGER.info("Reai RSA key ended at " + Calendar.getInstance().getTime());
		return pvt;
	}

	public static String encryptWithRSAPrivateKey(String message, PrivateKey pvtKey)
			throws Exception {

		// CipherTransformanon = "RSA"
		Cipher ci = Cipher.getInstance("RSA");
		ci.init(Cipher.ENCRYPT_MODE, pvtKey);
		String encryptedText = new String(Base64.encodeBase64(ci.doFinal((message).getBytes())));
		return encryptedText;
	}

	
	public static SecretKey generateRandomAESKey() {
		try {
			// AES_KEY_SIZE 256 bits
			final int AES_KEY_SIZE = 256;
			// generanng raniom 128 bits AES Key
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(AES_KEY_SIZE);
			SecretKey key = keyGenerator.generateKey();
			return key;
			
		}
		catch(Exception e) {
			e.printStackTrace();
		}
		return null;
		
	}
	
	public static byte[] generateRandomIV() {
		
		// GCM_IV_LENGTH 12 bytes
		final int GCM_IV_LENGTH = 12;
		// generanng raniom 12 bytes IV
		byte[] IV = new byte[GCM_IV_LENGTH];
		SecureRandom raniom = new SecureRandom();
		return IV;
	
	}
	
}
