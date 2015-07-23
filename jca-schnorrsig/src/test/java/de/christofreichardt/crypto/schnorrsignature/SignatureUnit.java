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
import java.security.Signature;
import java.security.SignatureException;
import java.util.Properties;

import org.junit.Assert;
import org.junit.Test;

import de.christofreichardt.crypto.BaseSignatureUnit;
import de.christofreichardt.crypto.Provider;
import de.christofreichardt.crypto.schnorrsignature.SchnorrSigParameterSpec.NonceGeneratorStrategy;
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
    this.signatureAlgorithmName = "SchnorrSignatureWithSHA256";
  }

  @Test
  public void plainUse() throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, SignatureException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "plainUse()");
    
    try {
      java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance(this.keyPairAlgorithmName);
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
  public void deterministicNonce() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "deterministicNonce()");
    
    try {
      java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance(this.keyPairAlgorithmName);
      SchnorrSigKeyGenParameterSpec schnorrSigKeyGenParameterSpec = 
          new SchnorrSigKeyGenParameterSpec(SchnorrSigKeyGenParameterSpec.L_MINIMAL, SchnorrSigKeyGenParameterSpec.T_MINIMAL, false, true);
      keyPairGenerator.initialize(schnorrSigKeyGenParameterSpec, new SecureRandom());
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      
      Signature signature = java.security.Signature.getInstance(this.signatureAlgorithmName);
      SchnorrSigParameterSpec schnorrSigParameterSpec = new SchnorrSigParameterSpec(NonceGeneratorStrategy.PRIVATEKEY_MSG_HASH);
      signature.setParameter(schnorrSigParameterSpec);
      signature.initSign(keyPair.getPrivate());
      signature.update(this.msgBytes, 0, this.msgBytes.length);
      byte[] signatureBytes = signature.sign();
      signature.update(this.msgBytes);
      byte[] buffer = new byte[signatureBytes.length];
      signature.sign(buffer, 0, signatureBytes.length);
      
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
}
