package com.mywork;

import java.security.PrivateKey;
import java.security.PublicKey;

public class ReconFileDecrypt {

	public static void main(String[] args) {
		try {
			PrivateKey privateKey = Encryption.readRSAPrivateKeyPEM("/home/ajinkyakarode/Documents/Ajinkya/SBI/reconFileEncrypt/privateNew.pem");
			PublicKey destinationPubKey = Encryption.readRSAPublicKeyfromCert("/home/ajinkyakarode/Documents/Ajinkya/SBI/reconFileEncrypt/public.cer");
			String hashDec = Decryption.decryptWithRSAPublicKey("0DdQHgUADcNVNHQCE7NbGLKibpFQc2D1Y1HJ7XhfmOwUe70qqtxA+6PRDsmPwtQqBQm2PNnj9dg4XkB8oJ5UyQ1wIMPVKgcSoP0SGUG9FMzBu1Q2wtDMaOy/80P5pR2pdyM+QqgUb0lSBQ0f7q7PO161HHI7uq9/y8JANza4Nji/rNK0oIznGHfuXsVBaxtcBUyanvpXI0WjOoSYgj5E0jH9hHm3SGqcUh4S8QEqKgfOORWHfTB0NHuc6sUdwq0JJc453yO4XmGYNLermbMggJU4o2dR37lPaNXnTmOElJRuKaTxO15meoc5D+cVZTDgyHpt/ytX1jz2ivUHGyq+SQ==", 
					destinationPubKey);
			System.out.println("hashDec : "+hashDec);
			
			
			String keyIvDec = Decryption.decryptWithRSAPrivateKey("YXUKc5F5CxaL7l2ekf004DaVJzQUrJWgda/+wbspyRMdggTG2iBrkQb49ujMZq8sGIgyR2Xidn3N+Obg341F4v+mem0cpF9yln2iH7wRZdMINTaC1cRfmnUrTDNNZFOC8X63shtDbnDCmg0XBwr/5MTpHcYbc8G6qzGu/Uu4TUhItn71vQRhkCNdceDEWTvlAWrIQ/88SyU+Zed7zJI9vgxhNqmJEmVbG6xRST50GmrXdRdziNqqW3ZXCqALnj36dsM04zg6G8zxLALLo0ooKdL8da+qRhzbVzR/v1/X9sEtTxMUKHYcyolzuT4NaW4VRTezjG/kEa6R2ApFccn83A==",
					privateKey);
			
			System.out.println(keyIvDec);
			String[] res  = keyIvDec.split("\\|");
			System.out.println(res[0] + " , "+res[1]);
			
			Decryption.processFileAESDecryptBase64("/home/ajinkyakarode/Documents/Ajinkya/SBI/reconFileEncrypt/ReconTestEnc.txt", 
											"/home/ajinkyakarode/Documents/Ajinkya/SBI/reconFileEncrypt/ReconTestDec.txt", res[0], res[1]);
		}catch(Exception e) {
			e.printStackTrace();
		}
		
		
	}
}
