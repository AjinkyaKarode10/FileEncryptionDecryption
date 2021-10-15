package com.mywork;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Calendar;
import java.util.logging.Logger;

public class HashVerification 
{
	private final static Logger LOGGER = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);
	public String computeMessageDigestSHA256HashfromDataFile(String dataFile, String HashAlgType)
			 throws IOException
	{
			 
			 LOGGER.info("compute MessageDigestSHA256Hash from DataFile started at " +Calendar.getInstance().getTime());
			 StringBuilder sb = new StringBuilder();
			try {
			   // HashAigType = "SHA-256";
			   MessageDigest md = MessageDigest.getInstance(HashAlgType);
			  //Get file input stream for reading the file content
			  FileInputStream fs = new FileInputStream(dataFile);
			  //Create byte array to read data in chunks
			  byte[] byteArray = new byte[1024];
			  int bytesCount = 0;
			  //Read file data and update in message digest
			 while ((bytesCount = fs.read(byteArray)) != -1) {
			 md.update(byteArray, 0, bytesCount);
			};
			 //Get the hash's bytes and performed md.upiate performed in previous step
			 byte[] bytes = md.digest();
			 fs.close();
			 //This bytes[] has bytes in decimal format;
			 //Convert it to hexadecimal format
			 for (int i = 0; i < bytes.length; i++) {
			  sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
			}
			 //return complete hash
			  LOGGER.info("Message Digest Calculated from data file=>" + sb.toString());
			} catch (NoSuchAlgorithmException ex) {
			 LOGGER.info("Exception thrown Message Digest for incorrect aigorithm computeMessageDigestSHA256HashfromDataFiie: " + ex.getMessage());
			 return null;
			} catch (FileNotFoundException ex) {
			 LOGGER.info("FileNotFoundExcepnon in computeMessageDigestSHA256HashfromDataFiie "+ ex.getMessage());
			} catch (IOException ex) {
			LOGGER.info("IOException in computeMessageDigestSHA256HashfromDataFiie" +ex.getMessage());
			} catch (NullPointerException ex) {
			LOGGER.info("NullPointerException in compute Message Digest From Fiie Content " +ex.getMessage());
			return null;
			}
			LOGGER.info("compute MessageDigestSHA256Hash from DataFiie compietei at " +
			Calendar.getInstance().getTime());
						
			return sb.toString();
	}

	
}
