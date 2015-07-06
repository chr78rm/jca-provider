package de.christofreichardt.crypto.ecschnorrsignature;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Properties;

import org.junit.Assert;
import org.junit.Test;

import de.christofreichardt.crypto.BaseSignatureUnit;
import de.christofreichardt.crypto.Provider;
import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;

public class SignatureUnit extends BaseSignatureUnit implements Traceable {

  public SignatureUnit(Properties properties) {
    super(properties, new Provider());
    this.keyPairAlgorithmName = "ECSchnorrSignature";
    this.signatureAlgorithmName = "ECSchnorrSignatureWithSHA256";
  }
  
  @Test
  public void plainUse() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "plainUse()");
    
    try {
      SignatureWithSHA256 signatureWithSHA256 = new SignatureWithSHA256();
      KeyPairGenerator keyPairGenerator = new KeyPairGenerator();
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      
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
  
}
