package de.christofreichardt.crypto.schnorrsignature;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;

public class RandomNonceGenerator implements NonceGenerator, Traceable {
  private BigInteger modul;
  private SecureRandom secureRandom;
  
  public RandomNonceGenerator() {
  }
  
  public RandomNonceGenerator(BigInteger modul, SecureRandom secureRandom) {
    reset(secureRandom, modul, null);
  }

  @Override
  public BigInteger nonce() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("BigInteger", this, "nonce()");
    
    try {
      return new BigInteger(this.modul.bitLength()*2, this.secureRandom).mod(this.modul);
    }
    finally {
      tracer.wayout();
    }
  }

  @Override
  public void update(byte input) {
  }

  @Override
  public void update(byte[] bytes, int offset, int length) {
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
    this.secureRandom = secureRandom;
  }
}
