package com.sundayliu.x509certtest;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import android.os.Bundle;
import android.app.Activity;
import android.util.Log;
import android.view.Menu;

public class MainActivity extends Activity {
    private static final String DEBUG_TAG = "X509CertTest";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        verifyCert();
        //Log.e(DEBUG_TAG, "Verify result:" + result);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }
    
    public boolean verifyCert(){
        boolean ret = verifyCert("test.SF", "test_signed.bin", "test_cert.der", "SHA1withRSA");
        Log.e(DEBUG_TAG, "Verify TEST result:" + ret);
        
        ret = verifyCert("RSA.SF", "RSA.sign", "RSA.der", "SHA1withRSA");
        Log.e(DEBUG_TAG, "Verify RSA result:" + ret);
        
        ret = verifyCert("DSA.SF", "DSA.sign", "DSA.der", "SHA1withDSA");
        Log.e(DEBUG_TAG, "Verify DSA result:" + ret);
        
        ret = verifyCert("EC.SF", "EC.sign", "EC.der", "SHA256withECDSA");
        Log.e(DEBUG_TAG, "Verify ECDSA result:" + ret);
        return false;
    }
    
    public boolean verifyCert(String signDataName, String signedDataName, String certName, String algorithm){
        
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
