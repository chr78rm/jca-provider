package de.christofreichardt.crypto.schnorrsignature;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;

public class SHA1PRNGNonceGenerator extends DeterministicNonceGenerator implements Traceable {
  private BigInteger modul;
  private SecureRandom secureRandom;
  
  public SHA1PRNGNonceGenerator() {
  }

  @Override
  public void update(byte input) {
  }

  @Override
  public void update(byte[] bytes, int offset, int length) {
  }

  @Override
  public BigInteger nonce() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("BigInteger", this, "nonce()");
    
    try {
      BigInteger nonce;
      int l = this.modul.bitLength();
      
      tracer.out().printfIndentln("l = %s", l);
      
      do {
        nonce = new BigInteger(l, this.secureRandom);
        
        tracer.out().printfIndentln("nonce = %s", nonce);
      } while (nonce.compareTo(this.modul) != -1);
      
      return nonce;
    }
    finally {
      tracer.wayout();
    }
  }
  
  @Override
  public void copy(MessageDigest messageDigest) throws SignatureException {
    try {
      byte[] digestBytes = ((MessageDigest) messageDigest.clone()).digest();
      this.secureRandom.setSeed(digestBytes);
    }
    catch (CloneNotSupportedException ex) {
      throw new SignatureException(ex);
    }
  }

  @Override
  public AbstractTracer getCurrentTracer() {
    return TracerFactory.getInstance().getCurrentPoolTracer();
  }

  @Override
  public void reset(SecureRandom secureRandom, BigInteger modul, SchnorrPrivateKey schnorrPrivateKey) {
    if (!(schnorrPrivateKey instanceof ExtSchnorrPrivateKey))
      throw new RuntimeException("Need a ExtSchnorrPrivateKey instance.");
    
    this.modul = modul;
    try {
      this.secureRandom = SecureRandom.getInstance("SHA1PRNG");
      this.secureRandom.setSeed(((ExtSchnorrPrivateKey) schnorrPrivateKey).getExtKeyBytes());
    }
    catch (NoSuchAlgorithmException ex) {
      throw new RuntimeException(ex);
    }
  }

}
