package com.sundayliu.x509;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;



public class Main {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		System.out.println("Hello,World!");
		parsePKCS7("test.RSA", "test.SF");
	}
	
	public static void parsePKCS7(String pkcs7Path, String signPath){
		try{
			File f = new File("test_cert.der");
			FileInputStream is = new FileInputStream(f);
			byte[] cert = new byte[(int)f.length()];
			is.read(cert);
			is.close();
			
			f = new File("test_signed.bin");
			is = new FileInputStream(f);
			byte[] signedData = new byte[(int)f.length()];
			is.read(signedData);
			is.close();
			
			f = new File("test.SF");
			is = new FileInputStream(f);
			byte[] signData = new byte[(int)f.length()];
			is.read(signData);
			is.close();
			
			boolean result = verifySignedData(signData, signedData,cert);
			System.out.println("verified:" + result);
		}
		catch(Exception e){
			e.printStackTrace();
		}
		
	}
	
	public static boolean verifySignedData(byte[] signData, byte[] signedData, byte[] cert){
		boolean result = false;
		try{
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			InputStream ois = new ByteArrayInputStream(cert);
			X509Certificate oCert = (X509Certificate)cf.generateCertificate(ois);
			Signature oSign = Signature.getInstance("SHA1withRSA");
			oSign.initVerify(oCert);
			oSign.update(signData);
			result = oSign.verify(signedData);
		}
		catch(Exception e){
			e.printStackTrace();
		}
		return result;
	}

}
