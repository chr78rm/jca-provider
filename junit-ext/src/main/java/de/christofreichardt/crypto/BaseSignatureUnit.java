package de.christofreichardt.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Properties;
import java.util.Random;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.LogLevel;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;

public class BaseSignatureUnit implements Traceable {
  final protected Properties properties;
  
  protected byte[] msgBytes;
  protected byte[] spoiledMsgBytes;
  protected String keyPairAlgorithmName;
  protected String signatureAlgorithmName;
  protected java.security.Provider provider;

  public BaseSignatureUnit(Properties properties, java.security.Provider provider) {
    this.properties = properties;
    this.provider = provider;
  }
  
  @Before
  public void init() throws IOException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "init()");
    
    try {
      Security.addProvider(this.provider);
      this.msgBytes = loadMsgBytes();
      this.spoiledMsgBytes = spoilMsgBytes();
    }
    finally {
      tracer.wayout();
    }
  }
  
  protected byte[] loadMsgBytes() throws IOException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("byte[]", this, "loadMsgBytes()");
    
    try {
      File blindTextFile = new File(this.properties.getProperty("de.christofreichardt.crypto.schnorrsignature.SignatureUnit.blindtext", 
          "../data/loremipsum.txt"));
      byte[] bytes = Files.readAllBytes(blindTextFile.toPath());
      traceMsgBytes(bytes);
      return bytes;
    }
    finally {
      tracer.wayout();
    }
  }
  
  protected byte[] spoilMsgBytes() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("byte[]", this, "spoilMsgBytes()");
    
    try {
      byte[] bytes = Arrays.copyOf(this.msgBytes, this.msgBytes.length);
      Random random = new Random();
      int index = random.nextInt(bytes.length);
      byte spoiledByte;
      do {
        if ((spoiledByte = (byte) random.nextInt()) != bytes[index]) {
          bytes[index] = spoiledByte;
          break;
        }
      } while(true);
      traceMsgBytes(bytes);
      
      return bytes;
    }
    finally {
      tracer.wayout();
    }
  }
  
  private void traceMsgBytes(byte[] bytes) {
    AbstractTracer tracer = getCurrentTracer();
    for (int i=0; i<bytes.length; i++) {
      if (i % 16 == 0) {
        if (i != 0)
          tracer.out().println();
        tracer.out().printIndentString();
      }
      tracer.out().printf("%3d ", bytes[i] & 255);
    }
    tracer.out().println();
  }
  
  @Test
  public void providerByAlgorithm() throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, SignatureException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "providerByAlgorithm()");
    
    try {
      java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance(this.keyPairAlgorithmName);
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      
      Signature signature = Signature.getInstance(this.signatureAlgorithmName);
      byte[] signatureBytes = sign(signature, keyPair.getPrivate(), this.msgBytes);
      boolean verified = verify(signature, keyPair.getPublic(), this.msgBytes, signatureBytes);
      
      Assert.assertTrue("Expected a valid signature.", verified);
      
      verified = verify(signature, keyPair.getPublic(), this.spoiledMsgBytes, signatureBytes);
      
      Assert.assertTrue("Expected an invalid signature.", !verified);
    }
    finally {
      tracer.wayout();
    }
  }

  @Test
  public void providerByAlgorithmAndProvider() throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, SignatureException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "providerByAlgorithmAndProvider()");

    try {
      java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance(this.keyPairAlgorithmName);
      KeyPair keyPair = keyPairGenerator.generateKeyPair();

      Signature signature = Signature.getInstance(this.signatureAlgorithmName, this.provider);
      byte[] signatureBytes = sign(signature, keyPair.getPrivate(), this.msgBytes);
      boolean verified = verify(signature, keyPair.getPublic(), this.msgBytes, signatureBytes);

      Assert.assertTrue("Expected a valid signature.", verified);

      verified = verify(signature, keyPair.getPublic(), this.spoiledMsgBytes, signatureBytes);

      Assert.assertTrue("Expected an invalid signature.", !verified);
    }
    finally {
      tracer.wayout();
    }
  }

  @Test
  public void providerByAlgorithmAndProvidername() throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, SignatureException, NoSuchProviderException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "providerByAlgorithmAndProvidername()");

    try {
      java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance(this.keyPairAlgorithmName);
      KeyPair keyPair = keyPairGenerator.generateKeyPair();

      Signature signature = Signature.getInstance(this.signatureAlgorithmName, this.provider.getName());
      byte[] signatureBytes = sign(signature, keyPair.getPrivate(), this.msgBytes);
      boolean verified = verify(signature, keyPair.getPublic(), this.msgBytes, signatureBytes);

      Assert.assertTrue("Expected a valid signature.", verified);

      verified = verify(signature, keyPair.getPublic(), this.spoiledMsgBytes, signatureBytes);

      Assert.assertTrue("Expected an invalid signature.", !verified);
    }
    finally {
      tracer.wayout();
    }
  }

  @Test
  public void falseKey() throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, SignatureException, NoSuchProviderException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "falseKey()");

    try {
      java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance(this.keyPairAlgorithmName);
      KeyPair keyPair = keyPairGenerator.generateKeyPair();

      Signature signature = Signature.getInstance(this.signatureAlgorithmName, this.provider.getName());
      byte[] signatureBytes = sign(signature, keyPair.getPrivate(), this.msgBytes);
      boolean verified = verify(signature, keyPair.getPublic(), this.msgBytes, signatureBytes);

      Assert.assertTrue("Expected a valid signature.", verified);

      keyPair = keyPairGenerator.generateKeyPair();
      verified = verify(signature, keyPair.getPublic(), this.spoiledMsgBytes, signatureBytes);

      Assert.assertTrue("Expected an invalid signature.", !verified);
    }
    finally {
      tracer.wayout();
    }
  }

  @Test
  public void nio() throws NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeyException, SignatureException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "nio()");

    try {
      if (this.properties.containsKey("de.christofreichardt.crypto.BaseSignatureUnit.document")) {
        java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance(this.keyPairAlgorithmName);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        Signature signature = Signature.getInstance(this.signatureAlgorithmName, this.provider.getName());
        signature.initSign(keyPair.getPrivate());
        
        File file = new File(this.properties.getProperty("de.christofreichardt.crypto.BaseSignatureUnit.document"));
        Assert.assertTrue("Specified file '" + file.getPath() + "' doesn't exist.", file.exists());
        
        int bufferSize = 512;
        ByteBuffer buffer = ByteBuffer.allocate(bufferSize);
        byte[] bytes = new byte[bufferSize];
        try (FileInputStream fileInputStream = new FileInputStream(file)) {
          FileChannel fileChannel = fileInputStream.getChannel();
          do {
            int read = fileChannel.read(buffer);
            
            tracer.out().printfIndentln("read = %d", read);
            
            if (read == -1)
              break;
            buffer.flip();
            buffer.get(bytes, 0, read);
            
            tracer.out().printIndent("bytes: ");
            for (int i=0; i<read; i++) {
              tracer.out().print(bytes[i] & 255);
              tracer.out().print(" ");
            }
            tracer.out().println();
            
            signature.update(bytes, 0, read);
            buffer.clear();
          } while(true);
        }
        
        byte[] signatureBytes = signature.sign();
        signature.initVerify(keyPair.getPublic());
        
        try (FileInputStream fileInputStream = new FileInputStream(file)) {
          FileChannel fileChannel = fileInputStream.getChannel();
          do {
            int read = fileChannel.read(buffer);
            
            tracer.out().printfIndentln("read = %d", read);
            
            if (read == -1)
              break;
            buffer.flip();
            buffer.get(bytes, 0, read);
            
            tracer.out().printIndent("bytes: ");
            for (int i=0; i<read; i++) {
              tracer.out().print(bytes[i] & 255);
              tracer.out().print(" ");
            }
            tracer.out().println();
            
            signature.update(bytes, 0, read);
            buffer.clear();
          } while(true);
        }
        
        boolean verified = signature.verify(signatureBytes);
        Assert.assertTrue("Expected a valid signature.", file.exists());
      }
      else
        tracer.logMessage(LogLevel.INFO, "Nio testcase skipped.", getClass(), "void nio()");
    }
    finally {
      tracer.wayout();
    }
  }
  
  protected byte[] sign(Signature signature, PrivateKey privateKey, byte[] msgBytes) throws InvalidKeyException, SignatureException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("byte[]", this, "sign(Signature signature, PrivateKey privateKey, byte[] msgBytes)");
    
    try {
      signature.initSign(privateKey);
      signature.update(msgBytes);
      byte[] signatureBytes = signature.sign();
      
      return signatureBytes;
    }
    finally {
      tracer.wayout();
    }
  }
  
  protected boolean verify(Signature signature, PublicKey publicKey, byte[] msgBytes, byte[] signatureBytes) throws InvalidKeyException, SignatureException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("boolean", this, "verify(Signature signature, PublicKey publicKey, byte[] msgBytes, byte[] signatureBytes)");
    
    try {
      signature.initVerify(publicKey);
      signature.update(msgBytes);
      boolean verified = signature.verify(signatureBytes);
      
      return verified;
    }
    finally {
      tracer.wayout();
    }
  }
  
  @After
  public void exit() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "exit()");
    
    try {
      Security.removeProvider(this.provider.getName());
    }
    finally {
      tracer.wayout();
    }
  }

  @Override
  public AbstractTracer getCurrentTracer() {
    return TracerFactory.getInstance().getCurrentPoolTracer();
  }
}
