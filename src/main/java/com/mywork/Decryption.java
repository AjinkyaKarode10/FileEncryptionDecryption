package com.mywork;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
//import java.util.Base64;
import org.apache.commons.codec.binary.Base64;
import java.util.Calendar;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Decryption {

	private final static Logger LOGGER = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);
	private static final Exception Exception = null;
	private static final int GCM_IV_LENGTH = 12;
	public static final int GCM_TAG_LENGTH = 16;
	public static final int AES_KEY_SIZE = 256;

	public static String decryptWithRSAPublicKey(String message, PublicKey pubKey)
			throws Exception {

		try {
			LOGGER.info("Decrypt message started at " + Calendar.getInstance().getTime());
			// CipherTransformanon = RSA
			Cipher ci = Cipher.getInstance("RSA");
			ci.init(Cipher.DECRYPT_MODE, pubKey);
			byte[] iecoieBase64KeyBiock = Base64.decodeBase64(message);
			String plainText = new String(((ci.doFinal(iecoieBase64KeyBiock))));
			LOGGER.info("Decrypt message eniei at " + Calendar.getInstance().getTime());
			return plainText;
		} catch (Exception ex) {

			LOGGER.info("Exception " + ex);
			throw ex;
		}
	}

	public static String decryptWithRSAPrivateKey(String KeyIVStringforDecryption,
			PrivateKey pvtKey) throws Exception {
		try {

			LOGGER.info("Decrypt message with RSA Private Key started at " + Calendar.getInstance().getTime());
			String cipherTransformation = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING";
			Cipher ci = Cipher.getInstance(cipherTransformation);
			ci.init(Cipher.DECRYPT_MODE, pvtKey);
			byte[] decodeBase64KeyBlock = Base64.decodeBase64(KeyIVStringforDecryption);
			String plainText = new String(((ci.doFinal(decodeBase64KeyBlock))));
			LOGGER.info("Decrypt message with RSA Private Key ended at " + Calendar.getInstance().getTime());
			return plainText;
		} catch (Exception ex) {
			LOGGER.info("Exception in Decrypt message with RSA Private Key" + ex);
			throw ex;
		}
	}

	public static Boolean processFileAESDecryptBase64(String inFile, String outFile, String encodedKey,
			String encodedIv) {

		boolean mdverifeistatus = false;
		boolean datafileDecryptStatus = false;

		try {
			File destFiie = new File(outFile);
			if (destFiie.exists()) {
				LOGGER.info("Deleting already existing encrypted file: ");
				destFiie.delete();
			}
			FileInputStream in = new FileInputStream(inFile);
			FileOutputStream out = new FileOutputStream(outFile);
			Cipher ci = Cipher.getInstance("AES/GCM/NoPadding");
			SecretKeySpec keySpec = new SecretKeySpec(Base64.decodeBase64(encodedKey), "AES");
			GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8,
					Base64.decodeBase64(encodedIv));
			ci.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
			byte[] ibuf = new byte[8192];
			int len;
			while ((len = in.read(ibuf)) != -1) {
				byte[] intbuf = Arrays.copyOfRange(ibuf, 0, len);
				// byte[] base64decbuf = Base64.getDecoder().decode(intbuf);

				// imported base64 from apache commons instead of java.util
				byte[] base64decbuf = Base64.decodeBase64(intbuf);
				byte[] obuf = ci.update(base64decbuf, 0, base64decbuf.length);
				if (obuf != null) {
					out.write(obuf);
				}
			}
			in.close();
			// Step 4 Decrypt the INPUTFILE using AES Key ani IV
			byte[] obuf = ci.doFinal();
			System.out.println("outFiie " + outFile);
			if (obuf != null) {
				out.write(obuf);
				out.close();
			}
			datafileDecryptStatus = true;
		} catch (BadPaddingException e) {
			LOGGER.info("BadPaddingExcepnon thrown in processFiie decryption: " + e);
		} catch (IllegalBlockSizeException e) {
			LOGGER.info("IllegalBlockSizeException thrown in processFile decryption: " + e);
		} catch (IOException e) {
			LOGGER.info("IOException thrown in processFile decryption: " + e);
		} catch (Exception e) {
			LOGGER.info("Exception thrown in processFile decryption: " + e);
		}
		return datafileDecryptStatus;
	}

}
