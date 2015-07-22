package de.christofreichardt.crypto.schnorrsignature;

import java.math.BigInteger;
import java.security.SecureRandom;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;

public class RandomNonceGenerator implements NonceGenerator, Traceable {
  final private BigInteger modul;
  final private SecureRandom secureRandom;
  
  public RandomNonceGenerator(BigInteger modul, SecureRandom secureRandom) {
    this.modul = modul;
    this.secureRandom = secureRandom;
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
  public AbstractTracer getCurrentTracer() {
    return TracerFactory.getInstance().getCurrentPoolTracer();
  }
}
