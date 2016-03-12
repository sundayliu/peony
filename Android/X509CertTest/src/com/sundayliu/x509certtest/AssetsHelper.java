package com.sundayliu.x509certtest;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

import android.content.Context;

public class AssetsHelper {
    public static boolean GetAssetsFile(Context context, String filename, String outPath, boolean bReplace){
        try{
            InputStream in = context.getAssets().open(filename);
            File dir = new File(outPath);
            if (bReplace && (dir.exists())){
                dir.delete();
            }
            
            if (in.available() == 0){
                return false;
            }
            
            FileOutputStream out = new FileOutputStream(outPath);
            int read;
            byte[] buffer = new byte[4096];
            while ((read = in.read(buffer)) > 0){
                out.write(buffer, 0, read);
            }
            out.close();
            in.close();
            return true;
        }catch(IOException e){
            e.printStackTrace();
        }
        return false;
    }
}
