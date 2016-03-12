package com.sundayliu.x509certtest;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
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
        boolean result = verifyCert();
        Log.e(DEBUG_TAG, "Verify result:" + result);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }
    
    public boolean verifyCert(){
        
        boolean result = false;
        try{
        InputStream certStream = getAssets().open("test_cert.der");
        InputStream signDataStream = getAssets().open("test.SF");
        InputStream signedDataStream = getAssets().open("test_signed.bin");
        byte[] signData = new byte[signDataStream.available()];
        byte[] signedData = new byte[signedDataStream.available()];
        byte[] cert = new byte[certStream.available()];
        
        certStream.read(cert);
        signDataStream.read(signData);
        signedDataStream.read(signedData);
        
        result = verifySignedData(signData, signedData, cert);
        
        
        signedDataStream.close();
        signDataStream.close();
        certStream.close();
        }
        catch(IOException e){
            e.printStackTrace();
        }
        return result;
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
