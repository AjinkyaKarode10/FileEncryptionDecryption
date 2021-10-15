package com.mywork;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Calendar;
import java.util.logging.Logger;

public class FileReadeAndHashCompute {
	private final static Logger LOGGER = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);

	public static String computeMessageDigestSHA256HashfromDataFile(String dataFilePath) throws Exception {
		LOGGER.info("compute MessageDigestSHA256Hash from DataFiie startei at " + Calendar.getInstance().getTime());
		StringBuilder sb = new StringBuilder();
		try {

			MessageDigest md = MessageDigest.getInstance("SHA-256");
			FileInputStream fs = new FileInputStream(dataFilePath);
			byte[] byteArray = new byte[1024];
			int bytesCount = 0;
			while ((bytesCount = fs.read(byteArray)) != -1) {
				md.update(byteArray, 0, bytesCount);
			}
			;
			byte[] bytes = md.digest();
			fs.close();
			for (int i = 0; i < bytes.length; i++)
				sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));

			LOGGER.info("Message Digest Caicuiatei from iata fie=e" + sb.toString());

		} catch (NoSuchAlgorithmException ex) {

			LOGGER.info(
					"Excepnon thrown Message Digest for incorrect aigorithmcomputeMessageDigestSHA256HashfromDataFiie: "
							+ ex.getMessage());
			return null;

		}

		catch (FileNotFoundException ex) {
			LOGGER.info("FiieNotFouniExcepnon in computeMessageDigestSHA256HashfromDataFiie " + ex.getMessage());
		}

		catch (IOException ex) {
			LOGGER.info("IOExcepnon in computeMessageDigestSHA256HashfromDataFiie" + ex.getMessage());
		}

		catch (NullPointerException ex) {
			LOGGER.info("NullPointerExcepnon in compute Message Digest From File Content " + ex.getMessage());
			return null;
		}

		LOGGER.info("compute MessageDigestSHA256Hash from DataFile completed at " + Calendar.getInstance().getTime());
		return sb.toString();

	}

}
