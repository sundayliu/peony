package com.sundayliu.x509certtest;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Principal;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import android.os.Bundle;
import android.app.Activity;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
//import android.content.pm.Signature;
import android.util.Log;
import android.view.Menu;



public class MainActivity extends Activity {
    private static final String DEBUG_TAG = "X509CertTest";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        verifyCert();
        //dumpInfo();
        //Log.e(DEBUG_TAG, "Verify result:" + result);
        //DerInputStream s;
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }
    
    public void parseSignature(byte[] signature){
        try{
            
            Log.e(DEBUG_TAG, "size:" + signature.length);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            
            X509Certificate cert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(signature));
            Principal  p = cert.getSubjectDN();
            Log.e(DEBUG_TAG, p.getName());
        }
        catch(Exception e){
            e.printStackTrace();
        }
    }
    
    public void dumpInfo(){
        String packageName = getPackageName();
        Log.e(DEBUG_TAG, packageName);
        
        String packagePath = getPackageResourcePath();
        Log.e(DEBUG_TAG, packagePath);
        try{
            PackageManager pkgMgr = getPackageManager();
            if (pkgMgr == null){
                Log.e(DEBUG_TAG, "pkgMgr is null");
            }
            PackageInfo pkgInfo = pkgMgr.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
            
            if (pkgInfo == null){
                Log.e(DEBUG_TAG, "pkgInfo is null");
            }
            ProviderInfo[] providers = pkgInfo.providers;
            android.content.pm.Signature[] signatures = pkgInfo.signatures;
            if (providers == null){
                Log.e(DEBUG_TAG, "providers is null");
            }
            else{
                for (int i = 0; i < providers.length; i++){
                    ProviderInfo provider = providers[i];
                    Log.e(DEBUG_TAG, "Provider:" + provider.name);
                }
            }
            
            if (signatures == null){
                Log.e(DEBUG_TAG, "signature is null");
            }
            else{
                for (int i = 0; i < signatures.length; i++){
                    android.content.pm.Signature signature = signatures[i];
                    parseSignature(signature.toByteArray());
                    
                }
            }
            
            

        }
        catch(Exception e){
            e.printStackTrace();
        }
        
    }
    
    public boolean verifyCert(){
        boolean ret = verifyCert("test.SF", "test_signed.bin", "test_cert.der", "SHA1withRSA");
        verifyCert("test.SF", "test_signed.bin", "test_cert.der", "SHA1", "RSA");
        Log.e(DEBUG_TAG, "Verify TEST result:" + ret);
        
        //ret = verifyCert("RSA.SF", "RSA.sign", "RSA.der", "SHA1withRSA");
        verifyCert("RSA.SF", "RSA.sign", "RSA.der", "SHA1", "RSA");
        //Log.e(DEBUG_TAG, "Verify RSA result:" + ret);
        
        //ret = verifyCert("DSA.SF", "DSA.sign", "DSA.der", "SHA1withDSA");
        //verifyCert("DSA.SF", "DSA.sign", "DSA.der", "SHA1", "DSA");
        //Log.e(DEBUG_TAG, "Verify DSA result:" + ret);
        
        //ret = verifyCert("EC.SF", "EC.sign", "EC.der", "SHA256withECDSA");
        //verifyCert("EC.SF", "EC.sign", "EC.der", "SHA256", "ECDSA");
        //Log.e(DEBUG_TAG, "Verify ECDSA result:" + ret);
        return false;
    }
    
    public boolean verifyCert(String signDataName, String signedDataName, String certName, String algorithm){
        //return true;
        boolean result = false;
        try{
        InputStream certStream = getAssets().open(certName);
        InputStream signDataStream = getAssets().open(signDataName);
        InputStream signedDataStream = getAssets().open(signedDataName);
        byte[] signData = new byte[signDataStream.available()];
        byte[] signedData = new byte[signedDataStream.available()];
        byte[] cert = new byte[certStream.available()];
        
        certStream.read(cert);
        signDataStream.read(signData);
        signedDataStream.read(signedData);
        
        result = verifySignedData(signData, signedData, cert, algorithm);
        
        
        signedDataStream.close();
        signDataStream.close();
        certStream.close();
        }
        catch(IOException e){
            e.printStackTrace();
        }
        return result;
    }
    
    public boolean verifyCert(String signFileName, String signedFileName, String certFileName, String algDigest, String algEncrypt){
        try{
            InputStream isSign = getAssets().open(signFileName);
            byte[] signData = new byte[isSign.available()];
            isSign.read(signData);
            isSign.close();
            
            MessageDigest digestInstance = MessageDigest.getInstance(algDigest);
            digestInstance.update(signData);
            byte[] hash = digestInstance.digest();
            Log.e(DEBUG_TAG, "HASH:" + hexEncode(hash));
            
            InputStream isSigned = getAssets().open(signedFileName);
            byte[] signedData = new byte[isSigned.available()];
            isSigned.read(signedData);
            isSigned.close();
            
            Log.e(DEBUG_TAG, "signature data size:" + signedData.length);
            
            InputStream isCert = getAssets().open(certFileName);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate)cf.generateCertificate(isCert);
            isCert.close();
            
            PublicKey publicKey = cert.getPublicKey();
            
            byte[] decryptData = decryptByPublicKey(signedData, publicKey, algEncrypt);
            Log.e(DEBUG_TAG, "DECRYPT size:" + decryptData.length);
            Log.e(DEBUG_TAG, "DECRYPT:" + hexEncode(decryptData));
            
        }
        catch(Exception e){
            e.printStackTrace();
        }
        return true;
    }
    
    public static byte[] decryptByPublicKey(byte[] data, PublicKey key, String algName) throws Exception{
        Cipher cipher = Cipher.getInstance(algName);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }
    
    public static boolean verifySignedData(byte[] signData, byte[] signedData, byte[] cert, String algorithm){
        boolean result = false;
        try{
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            InputStream ois = new ByteArrayInputStream(cert);
            X509Certificate oCert = (X509Certificate)cf.generateCertificate(ois);
            
            MessageDigest digest = MessageDigest.getInstance("MD5");
            digest.update(oCert.getEncoded());
            byte[] hash = digest.digest();
            Log.e(DEBUG_TAG, "CERT MD5:" + hexEncode(hash));
            //digest.
            //String hexHash = Hex.encodeHexString(hash);
            
            Signature oSign = Signature.getInstance(algorithm);
            oSign.initVerify(oCert);
            oSign.update(signData);
            result = oSign.verify(signedData);
        }
        catch(Exception e){
            e.printStackTrace();
        }
        return result;
    }
    
    public static boolean verifySignedData(byte[] signData, byte[] signedData, byte[] cert){
        return verifySignedData(signData, signedData, cert, "SHA1withRSA");
    }
    
    public static String hexEncode(byte[] a){
        StringBuilder sb = new StringBuilder();
        for (byte b:a)
            sb.append(String.format("%02x", b & 0xff));
       return sb.toString();
    }

}
