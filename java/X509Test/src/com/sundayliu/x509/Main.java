package com.sundayliu.x509;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;

//import sun.security.rsa.*;

class RSACore{
	public static int getByteLength(BigInteger b){
		int n = b.bitLength();
		return (n + 7) >> 3;
	}
	
	public static int getByteLength(RSAKey key){
		return getByteLength(key.getModulus());
	}
	
    /**
     * Perform an RSA public key operation.
     */
    public static byte[] rsa(byte[] msg, RSAPublicKey key)
            throws BadPaddingException {
        return crypt(msg, key.getModulus(), key.getPublicExponent());
    }
    
    /**
     * RSA public key ops and non-CRT private key ops. Simple modPow().
     */
    private static byte[] crypt(byte[] msg, BigInteger n, BigInteger exp)
            throws BadPaddingException {
        BigInteger m = parseMsg(msg, n);
        BigInteger c = m.modPow(exp, n);
        return toByteArray(c, getByteLength(n));
    }
    
    /**
     * Parse the msg into a BigInteger and check against the modulus n.
     */
    private static BigInteger parseMsg(byte[] msg, BigInteger n)
            throws BadPaddingException {
        BigInteger m = new BigInteger(1, msg);
        if (m.compareTo(n) >= 0) {
            throw new BadPaddingException("Message is larger than modulus");
        }
        return m;
    }

    /**
     * Return the encoding of this BigInteger that is exactly len bytes long.
     * Prefix/strip off leading 0x00 bytes if necessary.
     * Precondition: bi must fit into len bytes
     */
    private static byte[] toByteArray(BigInteger bi, int len) {
        byte[] b = bi.toByteArray();
        int n = b.length;
        if (n == len) {
            return b;
        }
        // BigInteger prefixed a 0x00 byte for 2's complement form, remove it
        if ((n == len + 1) && (b[0] == 0)) {
            byte[] t = new byte[len];
            System.arraycopy(b, 1, t, 0, len);
            return t;
        }
        // must be smaller
        assert (n < len);
        byte[] t = new byte[len];
        System.arraycopy(b, 0, t, (len - n), n);
        return t;
    }
}
class RSASignature{
    private static final int baseLength = 8;

    // object identifier for the message digest algorithm used
    //private final ObjectIdentifier digestOID;

    // length of the encoded signature blob
    private final int encodedLength;

    // message digest implementation we use
    private final MessageDigest md;
    // flag indicating whether the digest is reset
    private boolean digestReset;

    // private key, if initialized for signing
    private RSAPrivateKey privateKey;
    // public key, if initialized for verifying
    private RSAPublicKey publicKey;

    // padding to use, set when the initSign/initVerify is called
    //private RSAPadding padding;
	
    /**
     * Construct a new RSASignature. Used by subclasses.
     */
    RSASignature(String algorithm,  int oidLength) {
        //this.digestOID = digestOID;
        try {
            md = MessageDigest.getInstance(algorithm);
            //AlgorithmId x
        } catch (NoSuchAlgorithmException e) {
            throw new ProviderException(e);
        }
        digestReset = true;
        encodedLength = baseLength + oidLength + md.getDigestLength();
    }

    // initialize for verification. See JCA doc
    public void engineInitVerify(PublicKey publicKey)
            throws InvalidKeyException {
        RSAPublicKey rsaKey = (RSAPublicKey)(publicKey);
        this.privateKey = null;
        this.publicKey = rsaKey;
        initCommon(rsaKey, null);
    }
    
    private void initCommon(RSAKey rsaKey, SecureRandom random)
            throws InvalidKeyException {
        //resetDigest();
//        int keySize = RSACore.getByteLength(rsaKey);
//        try {
//            padding = RSAPadding.getInstance
//                (RSAPadding.PAD_BLOCKTYPE_1, keySize, random);
//        } catch (InvalidAlgorithmParameterException iape) {
//            throw new InvalidKeyException(iape.getMessage());
//        }
//        int maxDataSize = padding.getMaxDataSize();
//        if (encodedLength > maxDataSize) {
//            throw new InvalidKeyException
//                ("Key is too short for this signature algorithm");
//        }
    }
	
	public boolean engineVerify(byte[] sigBytes) throws SignatureException{
		if (sigBytes.length != RSACore.getByteLength(publicKey)){
			return false;
		}
		
		try{
			byte[] decrypted = RSACore.rsa(sigBytes, publicKey);
			
			System.out.println("size:" + decrypted.length);
		}
		catch(Exception e){
			
		}
		return false;
	}
}
public class Main {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		System.out.println("Hello,World!");
		//parsePKCS7("test.RSA", "test.SF");
		
		//RSASignature s;
		//DerInputStream s;
		
		//verifyCert("test.SF","test_signed.bin","test_cert.der","SHA1","RSA");
		verifyCert("CERT.SF","signed-sha1.bin","cert.cer","SHA1","RSA");
	}
	
    public static String hexEncode(byte[] a){
        StringBuilder sb = new StringBuilder();
        for (byte b:a)
            sb.append(String.format("%02x", b & 0xff));
       return sb.toString();
    }
    
    public static byte toHex(byte m){
    	if (m >= '0' && m < '9'){
			m = (byte)(m - '0');
		}
		else if (m >= 'A' && m <= 'Z'){
			m = (byte)(m - 'A' + 10);
		}
		else if (m >= 'a' && m <= 'z'){
			m = (byte)(m - 'a' + 10);
		}
    	return m;
    }
    
    public static byte[] hexDecode(byte[] a){
    	byte[] result = new byte[a.length/2];
    	for (int i = 0; i < a.length; i+=2){
    		byte m = a[i];
    		byte n = a[i+1];
    		m = toHex(m);
    		n = toHex(n);
    		
    		result[i/2] = (byte)(m * 16 + n);
    	}
    	return result;
    }
	
	public static boolean verifyCert(String signFileName, String signedFileName, String certFileName, String algDigest, String algEncrypt){
        try{
            FileInputStream isSign = new FileInputStream(new File(signFileName));
            byte[] signData = new byte[isSign.available()];
            isSign.read(signData);
            isSign.close();
            
            MessageDigest digestInstance = MessageDigest.getInstance(algDigest);
            digestInstance.update(signData);
            byte[] hash = digestInstance.digest();
            System.out.println( "HASH size:" + hash.length);
            System.out.println( "HASH:" + hexEncode(hash));
            
            FileInputStream isSigned = new FileInputStream(new File(signedFileName));
            byte[] signedData = new byte[isSigned.available()];
            isSigned.read(signedData);
            isSigned.close();
            
           System.out.println("signature data size:" + signedData.length);
            
            InputStream isCert = new FileInputStream(new File(certFileName));
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate)cf.generateCertificate(isCert);
            isCert.close();
            
            PublicKey publicKey = cert.getPublicKey();
            
            byte[] decryptData = decryptByPublicKey(signData,signedData, publicKey, algEncrypt);
            System.out.println("DECRYPT size:" + decryptData.length);
            System.out.println("DECRYPT:" + hexEncode(decryptData));
            
//            byte[] signedData2 = hexDecode(signedData);
//            decryptData = decryptByPublicKey(signedData2, publicKey, algEncrypt);
//            System.out.println("DECRYPT size:" + decryptData.length);
//            System.out.println("DECRYPT:" + hexEncode(decryptData));
            
        }
        catch(Exception e){
            e.printStackTrace();
        }
        return true;
    }
    
    public static byte[] decryptByPublicKey(byte[] signData, byte[] data, PublicKey key, String algName) throws Exception{
        Cipher cipher = Cipher.getInstance(algName);
        cipher.init(Cipher.DECRYPT_MODE, key);
        //byte[] hash = cipher.update(signData, 0, signData.length);
        //System.out.println("DECRYPT size:" + hash.length);
        //System.out.println("DECRYPT:" + hexEncode(hash));
        byte[] out = cipher.doFinal(data);
        
        RSASignature rsa = new RSASignature("SHA1", 7);
        rsa.engineInitVerify(key);
        rsa.engineVerify(data);
        return out;
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
