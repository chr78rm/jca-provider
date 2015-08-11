package de.christofreichardt.crypto.schnorrsignature;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;

public class ExperimentalDeterministicNonceGenerator implements NonceGenerator, Traceable {
  private BigInteger modul;
  private MessageDigest messageDigest;
  final private byte[] extraBytes = {-46, 68, 13, 38, 81, -73, 12, -119, -27, -76, 73, 64, -50, -99, -48, -25, 4, -103, 40, 29, 23, 60, -14, -7, 88, -11, 90, -9, 
      -65, -58, 45, -79, -86, 71, -94, -10, 6, 106, 4, 34, -10, 36, 17, 127, -47, 95, 18, 4, 6, -126, -52, 26, 125, 104, -128, -86, -53, 95, 12, -104, 97, -112, 
      -47, -51, 26, -41, 11, 58, -127, 86, 90, 9, 60, 62, -54, 71, 68, -70, -119, -4, -31, 3, -93, 85, 72, -114, -104, -101, -83, 17, 25, -42, -18, -94, -100, -118, 
      106, -42, -113, 124, 87, 111, 97, -86, -83, -37, -40, -6, -44, -17, 49, -90, -115, -47, -86, -88, -13, 8, -4, 104, -88, 94, 31, 54, -74, 14, 30, -28};
  private int index = -1;
  
  public ExperimentalDeterministicNonceGenerator() {
  }
  
  public ExperimentalDeterministicNonceGenerator(BigInteger modul, byte[] extendedKey) {
    reset(null, modul, extendedKey);
  }

  @Override
  public BigInteger nonce() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("BigInteger", this, "nonce()");
    
    try {
      try {
        if (this.index >= 0  &&  index < this.extraBytes.length)
          this.messageDigest.update(this.extraBytes[index]);
        MessageDigest messageDigest = (MessageDigest) this.messageDigest.clone();
        this.index++;
        
        return new BigInteger(messageDigest.digest()).mod(this.modul);
      }
      catch (CloneNotSupportedException ex) {
        throw new RuntimeException(ex);
      }
    }
    finally {
      tracer.wayout();
    }
  }

  @Override
  public void update(byte input) {
    this.messageDigest.update(input);
  }

  @Override
  public void update(byte[] bytes, int offset, int length) {
    this.messageDigest.update(bytes, offset, length);
  }
  
  @Override
  public void copy(MessageDigest messageDigest) {
  }

  @Override
  public AbstractTracer getCurrentTracer() {
    return TracerFactory.getInstance().getCurrentPoolTracer();
  }

  @Override
  public void reset(SecureRandom secureRandom, BigInteger modul, byte[] extendedKey) {
    this.modul = modul;
    try {
      this.messageDigest = MessageDigest.getInstance("SHA-512");
      this.messageDigest.update(extendedKey);
    }
    catch (NoSuchAlgorithmException ex) {
      throw new RuntimeException(ex);
    }
  }

}
