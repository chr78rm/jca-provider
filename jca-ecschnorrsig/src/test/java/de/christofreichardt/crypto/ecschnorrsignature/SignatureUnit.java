package de.christofreichardt.crypto.ecschnorrsignature;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Properties;
import java.util.Random;

import org.junit.Assert;
import org.junit.Test;

import de.christofreichardt.crypto.BaseSignatureUnit;
import de.christofreichardt.crypto.Provider;
import de.christofreichardt.crypto.ecschnorrsignature.ECSchnorrSigKeyGenParameterSpec.CurveCompilation;
import de.christofreichardt.crypto.ecschnorrsignature.ECSchnorrSigParameterSpec.PointMultiplicationStrategy;
import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;

public class SignatureUnit extends BaseSignatureUnit implements Traceable {

  public SignatureUnit(Properties properties) {
    super(properties, new Provider());
    this.keyPairAlgorithmName = "ECSchnorrSignature";
    this.signatureAlgorithmName = "ECSchnorrSignature";
  }
  
  @Test
  public void plainUse() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "plainUse()");
    
    try {
      ECSchnorrSignature ecSchnorrSignature = new ECSchnorrSignature();
      KeyPairGenerator keyPairGenerator = new KeyPairGenerator();
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      
      ECSchnorrPublicKey ecSchnorrPublicKey = (ECSchnorrPublicKey) keyPair.getPublic();
      BigInteger order = ecSchnorrPublicKey.getEcSchnorrParams().getCurveSpec().getOrder();
      
      tracer.out().printfIndentln("order(%d) = %s", order.bitLength(), order);
      
      ecSchnorrSignature.engineInitSign(keyPair.getPrivate());
      ecSchnorrSignature.engineUpdate(this.msgBytes, 0, this.msgBytes.length);
      byte[] signatureBytes = ecSchnorrSignature.engineSign();
      
      tracer.out().printfIndentln("--- Signature(%d Bytes) ---", signatureBytes.length);
      traceBytes(signatureBytes);
      
      ecSchnorrSignature.engineInitVerify(keyPair.getPublic());
      ecSchnorrSignature.engineUpdate(this.msgBytes, 0, this.msgBytes.length);
      boolean verified = ecSchnorrSignature.engineVerify(signatureBytes);
      
      Assert.assertTrue("Expected a valid signature.", verified);
      
      ecSchnorrSignature.engineInitVerify(keyPair.getPublic());
      ecSchnorrSignature.engineUpdate(this.spoiledMsgBytes, 0, this.spoiledMsgBytes.length);
      verified = ecSchnorrSignature.engineVerify(signatureBytes);
      
      Assert.assertTrue("Expected an invalid signature.", !verified);
    }
    finally {
      tracer.wayout();
    }
  }
  
  @Test
  public void customKeySizes() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "customKeySizes()");
    
    try {
      java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance(this.keyPairAlgorithmName);
      int[] keySizes = {192, 224, 256, 384, 521};
      for (int keySize : keySizes) {
        keyPairGenerator.initialize(keySize, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        ECSchnorrPublicKey ecSchnorrPublicKey = (ECSchnorrPublicKey) keyPair.getPublic();
        BigInteger order = ecSchnorrPublicKey.getEcSchnorrParams().getCurveSpec().getOrder();
        BigInteger p = ecSchnorrPublicKey.getEcSchnorrParams().getCurveSpec().getCurve().p().bigInteger();
        
        tracer.out().printfIndentln("p(%d) = %s", p.bitLength(), p);
        tracer.out().printfIndentln("order(%d) = %s", order.bitLength(), order);
        
        Signature signature = Signature.getInstance(this.signatureAlgorithmName);
        byte[] signatureBytes = sign(signature, keyPair.getPrivate(), this.msgBytes);
        boolean verified = verify(signature, keyPair.getPublic(), this.msgBytes, signatureBytes);
        
        Assert.assertTrue("Expected a valid signature.", verified);
        
        verified = verify(signature, keyPair.getPublic(), this.spoiledMsgBytes, signatureBytes);
        
        Assert.assertTrue("Expected an invalid signature.", !verified);
        
        keyPair = keyPairGenerator.generateKeyPair();
        verified = verify(signature, keyPair.getPublic(), this.msgBytes, signatureBytes);
        
        Assert.assertTrue("Expected an invalid signature.", !verified);
      }
    }
    finally {
      tracer.wayout();
    }
  }
  
  @Test
  public void fixedPointStrategy() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidAlgorithmParameterException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "fixedPointStrategy()");
    
    try {
      java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance(this.keyPairAlgorithmName);
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      ECSchnorrPublicKey ecSchnorrPublicKey = (ECSchnorrPublicKey) keyPair.getPublic();
      BigInteger order = ecSchnorrPublicKey.getEcSchnorrParams().getCurveSpec().getOrder();
      
      tracer.out().printfIndentln("order(%d) = %s", order.bitLength(), order);
      
      Signature signature = Signature.getInstance(this.signatureAlgorithmName);
      signature.setParameter(new ECSchnorrSigParameterSpec(PointMultiplicationStrategy.FIXED_POINT));
      byte[] signatureBytes = sign(signature, keyPair.getPrivate(), this.msgBytes);
      boolean verified = verify(signature, keyPair.getPublic(), this.msgBytes, signatureBytes);
      
      Assert.assertTrue("Expected a valid signature.", verified);
      
      verified = verify(signature, keyPair.getPublic(), this.spoiledMsgBytes, signatureBytes);
      
      Assert.assertTrue("Expected an invalid signature.", !verified);
      
      keyPair = keyPairGenerator.generateKeyPair();
      verified = verify(signature, keyPair.getPublic(), this.msgBytes, signatureBytes);
      
      Assert.assertTrue("Expected an invalid signature.", !verified);
    }
    finally {
      tracer.wayout();
    }
  }
  
  @Test
  public void customBrainPoolCurves() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidAlgorithmParameterException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "customBrainPoolCurves()");
    
    try {
      java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance(this.keyPairAlgorithmName);
      String[] curveIds = {"brainpoolP160r1", "brainpoolP160t1", "brainpoolP192r1", "brainpoolP192t1", "brainpoolP224r1", "brainpoolP224t1",
          "brainpoolP256r1", "brainpoolP256t1", "brainpoolP320r1", "brainpoolP320t1", "brainpoolP384r1", "brainpoolP384t1", "brainpoolP512r1",
          "brainpoolP512t1"};
      for (String curveId : curveIds) {
        keyPairGenerator.initialize(new ECSchnorrSigKeyGenParameterSpec(CurveCompilation.BRAINPOOL, curveId));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        ECSchnorrPublicKey ecSchnorrPublicKey = (ECSchnorrPublicKey) keyPair.getPublic();
        BigInteger order = ecSchnorrPublicKey.getEcSchnorrParams().getCurveSpec().getOrder();
        BigInteger p = ecSchnorrPublicKey.getEcSchnorrParams().getCurveSpec().getCurve().p().bigInteger();
        
        tracer.out().printfIndentln("p(%d) = %s", p.bitLength(), p);
        tracer.out().printfIndentln("order(%d) = %s", order.bitLength(), order);
        
        Signature signature = Signature.getInstance(this.signatureAlgorithmName);
        byte[] signatureBytes = sign(signature, keyPair.getPrivate(), this.msgBytes);
        boolean verified = verify(signature, keyPair.getPublic(), this.msgBytes, signatureBytes);
        
        Assert.assertTrue("Expected a valid signature.", verified);
        
        verified = verify(signature, keyPair.getPublic(), this.spoiledMsgBytes, signatureBytes);
        
        Assert.assertTrue("Expected an invalid signature.", !verified);
        
        keyPair = keyPairGenerator.generateKeyPair();
        verified = verify(signature, keyPair.getPublic(), this.msgBytes, signatureBytes);
        
        Assert.assertTrue("Expected an invalid signature.", !verified);
      }
    }
    finally {
      tracer.wayout();
    }
  }
  
}
