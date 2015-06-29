/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package de.christofreichardt.crypto.schnorrsignature;

import de.christofreichardt.crypto.Provider;
import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
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

/**
 *
 * @author Christof Reichardt
 */
public class SignatureUnit implements Traceable {
  final private Properties properties;
  final Provider provider = new Provider();
  
  private byte[] msgBytes;
  private byte[] spoiledMsgBytes;

  public SignatureUnit(Properties properties) {
    this.properties = properties;
  }
  
  @Before
  public void init() throws UnsupportedEncodingException, IOException {
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
  
  private byte[] loadMsgBytes() throws IOException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("byte[]", this, "loadMsgBytes()");
    
    try {
      File blindTextFile = new File(this.properties.getProperty("de.christofreichardt.crypto.schnorrsignature.SignatureUnit.blindtext", 
          "./data/loremipsum.txt"));
      byte[] bytes = Files.readAllBytes(blindTextFile.toPath());
      traceMsgBytes(bytes);
      return bytes;
    }
    finally {
      tracer.wayout();
    }
  }
  
  private byte[] spoilMsgBytes() {
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
  public void plainUse() throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, SignatureException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "plainUse()");
    
    try {
      java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance("SchnorrSignature");
      KeyPair keyPair = keyPairGenerator.generateKeyPair();

      SignatureWithSHA256 signatureWithSHA256 = new SignatureWithSHA256();
      signatureWithSHA256.engineInitSign(keyPair.getPrivate());
      signatureWithSHA256.engineUpdate(this.msgBytes, 0, this.msgBytes.length);
      byte[] signatureBytes = signatureWithSHA256.engineSign();
      signatureWithSHA256.engineInitVerify(keyPair.getPublic());
      signatureWithSHA256.engineUpdate(this.msgBytes, 0, this.msgBytes.length);
      boolean verified = signatureWithSHA256.engineVerify(signatureBytes);
      
      Assert.assertTrue("Expected a valid signature.", verified);
      
      signatureWithSHA256.engineInitVerify(keyPair.getPublic());
      signatureWithSHA256.engineUpdate(this.spoiledMsgBytes, 0, this.spoiledMsgBytes.length);
      verified = signatureWithSHA256.engineVerify(signatureBytes);
      
      Assert.assertTrue("Expected an invalid signature.", !verified);
    }
    finally {
      tracer.wayout();
    }
  }
  
  @Test
  public void providerByAlgorithm() throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, SignatureException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "providerByAlgorithm()");
    
    try {
      java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance("SchnorrSignature");
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      
      Signature signature = Signature.getInstance("SchnorrSignatureWithSHA256");
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
      java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance("SchnorrSignature");
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      
      Signature signature = Signature.getInstance("SchnorrSignatureWithSHA256", this.provider);
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
      java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance("SchnorrSignature");
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      
      Signature signature = Signature.getInstance("SchnorrSignatureWithSHA256", this.provider.getName());
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
      java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance("SchnorrSignature");
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      
      Signature signature = Signature.getInstance("SchnorrSignatureWithSHA256", this.provider.getName());
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
  
  private byte[] sign(Signature signature, PrivateKey privateKey, byte[] msgBytes) throws InvalidKeyException, SignatureException {
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
  
  private boolean verify(Signature signature, PublicKey publicKey, byte[] msgBytes, byte[] signatureBytes) throws InvalidKeyException, SignatureException {
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
