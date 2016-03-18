package com.sundayliu.security.util.jar;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CoderResult;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Iterator;
import com.sundayliu.io.Streams;

public class Manifest implements Cloneable{
    static final int LINE_LENGTH_LIMIT = 72;
    
    private static final byte[] LINE_SEPARATOR = new byte[] {'\r', '\n'};
    
    private static final byte[] VALUE_SEPARATOR = new byte[] {':', ' '};
    
    private static final Field BAIS_BUF = getByteArrayInputStreamField("buf");
    private static final Field BAIS_POS = getByteArrayInputStreamField("pos");
    
    private static Field getByteArrayInputStreamField(String name){
        try{
            Field f = ByteArrayInputStream.class.getDeclaredField(name);
            f.setAccessible(true);
            return f;
        }catch(Exception e){
            throw new AssertionError(e);
        }
    }
    
    private Attributes mainAttributes = new Attributes();
    
    private HashMap<String, Attributes> entries = new HashMap<String, Attributes>();
    
    static class Chunk{
        int start;
        int end;
        
        Chunk(int start, int end){
            this.start = start;
            this.end = end;
        }
    }
    
    private HashMap<String, Chunk> chunks;
    
    private int mainEnd;
    
    public Manifest(){
        
    }
    
    public Manifest(InputStream is) throws IOException{
        read(is);
    }
    
    public Manifest(Manifest man){
        mainAttributes = (Attributes)man.mainAttributes.clone();
        entries = (HashMap<String, Attributes>)(HashMap<String,Attributes>)man.getEntries().clone();
    }
    
    Manifest(InputStream is, boolean readChunks) throws IOException{
        if (readChunks){
            chunks = new HashMap<String, Chunk>();
        }
        read(is);
    }
    
    public void clear(){
        entries.clear();
        mainAttributes.clear();
    }
    
    public Attributes getAttributes(String name){
        return getEntries().get(name);
    }
    
    public HashMap<String, Attributes> getEntries(){
        return entries;
    }
    
    public Attributes getMainAttributes(){
        return mainAttributes;
    }
    
    public Object clone(){
        return new Manifest(this);
    }
    
    public void write(OutputStream os) throws IOException{
        write(this, os);
    }
    
    public void read(InputStream is) throws IOException{
        byte[] buf;
        if (is instanceof ByteArrayInputStream){
            buf = exposeByteArrayInputStreamBytes((ByteArrayInputStream)is);
        }else {
            buf = Streams.readFullyNoClose(is);
        }
        
        if (buf.length == 0){
            return;
        }
        
        byte b = buf[buf.length - 1];
        if (b == 0 || b == 26){
            buf[buf.length - 1] = '\n';
        }
        
        ManifestReader im = new ManifestReader(buf, mainAttributes);
        mainEnd = im.getEndOfMainSection();
        im.readEntries(entries, chunks);
    }
    
    /**
     * Returns a byte[] containing all the bytes from a ByteArrayInputStream.
     * Where possible, this returns the actual array rather than a copy.
     */
    private static byte[] exposeByteArrayInputStreamBytes(ByteArrayInputStream bais) {
        byte[] buffer;
        synchronized (bais) {
            byte[] buf;
            int pos;
            try {
                buf = (byte[]) BAIS_BUF.get(bais);
                pos = BAIS_POS.getInt(bais);
            } catch (IllegalAccessException iae) {
                throw new AssertionError(iae);
            }
            int available = bais.available();
            if (pos == 0 && buf.length == available) {
                buffer = buf;
            } else {
                buffer = new byte[available];
                System.arraycopy(buf, pos, buffer, 0, available);
            }
            bais.skip(available);
        }
        return buffer;
    }

    /**
     * Returns the hash code for this instance.
     *
     * @return this {@code Manifest}'s hashCode.
     */
    @Override
    public int hashCode() {
        return mainAttributes.hashCode() ^ getEntries().hashCode();
    }

    /**
     * Determines if the receiver is equal to the parameter object. Two {@code
     * Manifest}s are equal if they have identical main attributes as well as
     * identical entry attributes.
     *
     * @param o
     *            the object to compare against.
     * @return {@code true} if the manifests are equal, {@code false} otherwise
     */
    @Override
    public boolean equals(Object o) {
        if (o == null) {
            return false;
        }
        if (o.getClass() != this.getClass()) {
            return false;
        }
        if (!mainAttributes.equals(((Manifest) o).mainAttributes)) {
            return false;
        }
        return getEntries().equals(((Manifest) o).getEntries());
    }

    Chunk getChunk(String name) {
        return chunks.get(name);
    }

    void removeChunks() {
        chunks = null;
    }

    int getMainAttributesEnd() {
        return mainEnd;
    }
    
    
    static void write(Manifest manifest, OutputStream out) throws IOException {
        CharsetEncoder encoder = StandardCharsets.UTF_8.newEncoder();
        ByteBuffer buffer = ByteBuffer.allocate(LINE_LENGTH_LIMIT);

        Attributes.Name versionName = Attributes.Name.MANIFEST_VERSION;
        String version = manifest.mainAttributes.getValue(versionName);
        if (version == null) {
            versionName = Attributes.Name.SIGNATURE_VERSION;
            version = manifest.mainAttributes.getValue(versionName);
        }
        if (version != null) {
            writeEntry(out, versionName, version, encoder, buffer);
            Iterator<?> entries = manifest.mainAttributes.keySet().iterator();
            while (entries.hasNext()) {
                Attributes.Name name = (Attributes.Name) entries.next();
                if (!name.equals(versionName)) {
                    writeEntry(out, name, manifest.mainAttributes.getValue(name), encoder, buffer);
                }
            }
        }
        out.write(LINE_SEPARATOR);
        Iterator<String> i = manifest.getEntries().keySet().iterator();
        while (i.hasNext()) {
            String key = i.next();
            writeEntry(out, Attributes.Name.NAME, key, encoder, buffer);
            Attributes attributes = manifest.entries.get(key);
            Iterator<?> entries = attributes.keySet().iterator();
            while (entries.hasNext()) {
                Attributes.Name name = (Attributes.Name) entries.next();
                writeEntry(out, name, attributes.getValue(name), encoder, buffer);
            }
            out.write(LINE_SEPARATOR);
        }
    }
    
    private static void writeEntry(OutputStream os, Attributes.Name name,
            String value, CharsetEncoder encoder, ByteBuffer bBuf) throws IOException{
        String nameString = name.getName();
        os.write(nameString.getBytes(StandardCharsets.US_ASCII));
        os.write(VALUE_SEPARATOR);

        encoder.reset();
        bBuf.clear().limit(LINE_LENGTH_LIMIT - nameString.length() - 2);

        CharBuffer cBuf = CharBuffer.wrap(value);

        while (true) {
            CoderResult r = encoder.encode(cBuf, bBuf, true);
            if (CoderResult.UNDERFLOW == r) {
                r = encoder.flush(bBuf);
            }
            os.write(bBuf.array(), bBuf.arrayOffset(), bBuf.position());
            os.write(LINE_SEPARATOR);
            if (CoderResult.UNDERFLOW == r) {
                break;
            }
            os.write(' ');
            bBuf.clear().limit(LINE_LENGTH_LIMIT - 1);
        }
    }
}
