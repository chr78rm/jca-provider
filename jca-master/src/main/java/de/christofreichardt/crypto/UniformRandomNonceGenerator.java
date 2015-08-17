package de.christofreichardt.crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.SignatureException;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;

public class UniformRandomNonceGenerator extends RandomNonceGenerator implements Traceable {
  private BigInteger modul;
  private SecureRandom secureRandom;

  @Override
  public void update(byte input) {
  }

  @Override
  public void update(byte[] bytes, int offset, int length) {
  }

  @Override
  public BigInteger nonce() throws SignatureException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("BigInteger", this, "nonce()");
    
    try {
      BigInteger nonce;
      do {
        nonce = new BigInteger(this.modul.bitLength(), this.secureRandom);
      } while (nonce.compareTo(this.modul) != -1);
      
      tracer.out().printfIndentln("nonce = %s", nonce);
      
      return nonce;
    }
    finally {
      tracer.wayout();
    }
  }

  @Override
  public void copy(MessageDigest messageDigest) throws SignatureException {
  }

  @Override
  public void reset(SecureRandom secureRandom, BigInteger modul, byte[] extKeyBytes) {
    this.modul = modul;
    this.secureRandom = secureRandom;
  }

  @Override
  public AbstractTracer getCurrentTracer() {
    return TracerFactory.getInstance().getCurrentPoolTracer();
  }

}
