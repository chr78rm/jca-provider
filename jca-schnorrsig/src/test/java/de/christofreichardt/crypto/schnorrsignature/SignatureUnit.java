/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package de.christofreichardt.crypto.schnorrsignature;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Properties;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;

import de.christofreichardt.crypto.BaseSignatureUnit;
import de.christofreichardt.crypto.HmacSHA256PRNGNonceGenerator;
import de.christofreichardt.crypto.Provider;
import de.christofreichardt.crypto.UniformRandomNonceGenerator;
import de.christofreichardt.crypto.schnorrsignature.SchnorrSigKeyGenParameterSpec.Strength;
import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;

/**
 *
 * @author Christof Reichardt
 */
public class SignatureUnit extends BaseSignatureUnit implements Traceable {

  public SignatureUnit(Properties properties) {
    super(properties, new Provider());
    this.keyPairAlgorithmName = "SchnorrSignature";
    this.signatureAlgorithmName = "SchnorrSignature";
  }

  @Test
  public void plainUse() throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, SignatureException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "plainUse()");
    
    try {
      java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance(this.keyPairAlgorithmName);
      KeyPair keyPair = keyPairGenerator.generateKeyPair();

      SchnorrSignature signatureWithSHA256 = new SchnorrSignature();
      signatureWithSHA256.engineInitSign(keyPair.getPrivate());
      signatureWithSHA256.engineUpdate(this.msgBytes, 0, this.msgBytes.length);
      byte[] signatureBytes = signatureWithSHA256.engineSign();
      
      tracer.out().printfIndentln("--- Signature(%d Bytes) ---", signatureBytes.length);
      traceBytes(signatureBytes);
      
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
  public void deterministicNonce() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "deterministicNonce()");
    
    try {
      java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance(this.keyPairAlgorithmName);
      SchnorrSigKeyGenParameterSpec schnorrSigKeyGenParameterSpec = 
          new SchnorrSigKeyGenParameterSpec(Strength.DEFAULT, true);
      keyPairGenerator.initialize(schnorrSigKeyGenParameterSpec);
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      
      java.security.Signature signature = java.security.Signature.getInstance(this.signatureAlgorithmName);
      SchnorrSigParameterSpec schnorrSigParameterSpec = new SchnorrSigParameterSpec(new HmacSHA256PRNGNonceGenerator());
      signature.setParameter(schnorrSigParameterSpec);
      signature.initSign(keyPair.getPrivate());
      signature.update(this.msgBytes, 0, this.msgBytes.length);
      byte[] signatureBytes = signature.sign();
      signature.update(this.msgBytes);
      byte[] buffer = new byte[signatureBytes.length];
      signature.sign(buffer, 0, signatureBytes.length);
      
      tracer.out().printfIndentln("--- Signature(%d Bytes) ---", signatureBytes.length);
      traceBytes(signatureBytes);
      
      Assert.assertArrayEquals("Expected identical signatures.", signatureBytes, buffer);
      
      signature.initVerify(keyPair.getPublic());
      signature.update(this.msgBytes, 0, this.msgBytes.length);
      boolean verified = signature.verify(signatureBytes);
      
      Assert.assertTrue("Expected a valid signature.", verified);
      
      signature.initVerify(keyPair.getPublic());
      signature.update(this.spoiledMsgBytes, 0, this.spoiledMsgBytes.length);
      verified = signature.verify(signatureBytes);
      
      Assert.assertTrue("Expected an invalid signature.", !verified);
    }
    finally {
      tracer.wayout();
    }
  }
  
  @Test
  public void uniformNonce() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "uniformNonce()");
    
    try {
      java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance(this.keyPairAlgorithmName);
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      
      java.security.Signature signature = java.security.Signature.getInstance(this.signatureAlgorithmName);
      SchnorrSigParameterSpec schnorrSigParameterSpec = new SchnorrSigParameterSpec(new UniformRandomNonceGenerator());
      signature.setParameter(schnorrSigParameterSpec);
      signature.initSign(keyPair.getPrivate(), new SecureRandom());
      signature.update(this.msgBytes, 0, this.msgBytes.length);
      byte[] signatureBytes = signature.sign();
      signature.update(this.msgBytes);
      byte[] testBytes = signature.sign();
      
      tracer.out().printfIndentln("--- Signature(%d Bytes) ---", signatureBytes.length);
      traceBytes(signatureBytes);
      
      Assert.assertFalse("Expected non-identical signatures.", Arrays.equals(signatureBytes, testBytes));
      
      signature.initVerify(keyPair.getPublic());
      signature.update(this.msgBytes, 0, this.msgBytes.length);
      boolean verified = signature.verify(signatureBytes);
      
      Assert.assertTrue("Expected a valid signature.", verified);
      
      signature.initVerify(keyPair.getPublic());
      signature.update(this.spoiledMsgBytes, 0, this.spoiledMsgBytes.length);
      verified = signature.verify(signatureBytes);
      
      Assert.assertTrue("Expected an invalid signature.", !verified);
    }
    finally {
      tracer.wayout();
    }
  }
  
  @Test
  public void skeinDigest() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "skeinDigest()");
    
    try {
      Security.addProvider(new BouncyCastleProvider());
      java.security.Provider provider = Security.getProvider(de.christofreichardt.crypto.Provider.NAME);
      String algorithmName = provider.getProperty("de.christofreichardt.crypto.schnorrsignature.messageDigest", "SHA-256");
      provider.put("de.christofreichardt.crypto.schnorrsignature.messageDigest", "Skein-1024-1024");
      
      try {
        java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance(this.keyPairAlgorithmName);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        
        java.security.Signature signature = java.security.Signature.getInstance(this.signatureAlgorithmName);
        signature.initSign(keyPair.getPrivate());
        signature.update(this.msgBytes, 0, this.msgBytes.length);
        byte[] signatureBytes = signature.sign();
        
        tracer.out().printfIndentln("--- Signature(%d Bytes) ---", signatureBytes.length);
        traceBytes(signatureBytes);
        
        signature.initVerify(keyPair.getPublic());
        signature.update(this.msgBytes, 0, this.msgBytes.length);
        boolean verified = signature.verify(signatureBytes);
        
        Assert.assertTrue("Expected a valid signature.", verified);
        
        signature.initVerify(keyPair.getPublic());
        signature.update(this.spoiledMsgBytes, 0, this.spoiledMsgBytes.length);
        verified = signature.verify(signatureBytes);
        
        Assert.assertTrue("Expected an invalid signature.", !verified);
      }
      finally {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        provider.put("de.christofreichardt.crypto.schnorrsignature.messageDigest", algorithmName);
      }
    }
    finally {
      tracer.wayout();
    }
  }
}
