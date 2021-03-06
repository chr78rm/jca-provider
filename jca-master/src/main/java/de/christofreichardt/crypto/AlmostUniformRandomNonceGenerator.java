package de.christofreichardt.crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;

/**
 * Computes random nonces which are almost uniformly distributed over \u2124<sub>q</sub> in constant time.
 * 
 * @author Christof Reichardt
 */
public class AlmostUniformRandomNonceGenerator extends RandomNonceGenerator implements Traceable {
  private BigInteger modul;
  private SecureRandom secureRandom;
  
  public AlmostUniformRandomNonceGenerator() {
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
  public void reset(SecureRandom secureRandom, BigInteger modul, byte[] extKeyBytes) {
    this.modul = modul;
    this.secureRandom = secureRandom;
  }
}
