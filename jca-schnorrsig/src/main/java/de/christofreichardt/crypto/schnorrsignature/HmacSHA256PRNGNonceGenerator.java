package de.christofreichardt.crypto.schnorrsignature;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;

public class HmacSHA256PRNGNonceGenerator implements NonceGenerator, Traceable {
  final private BigInteger modul;
  final private Mac hmac;
  final private byte[] extendedKey;
  public static final String ALGORITHM_NAME = "HmacSHA256";
  
  private byte[] digestBytes;
  private byte[] vBytes;
  private byte[] kBytes;
  
  public HmacSHA256PRNGNonceGenerator(BigInteger modul, byte[] extendedKey) {
    this.modul = modul;
    this.extendedKey = extendedKey;
    try {
      String algorithmName = "HmacSHA256";
      this.hmac = Mac.getInstance(algorithmName);
      this.vBytes = new byte[this.hmac.getMacLength()];
      Arrays.fill(vBytes, (byte) 0x01);
      this.kBytes = new byte[this.hmac.getMacLength()];
      Arrays.fill(kBytes, (byte) 0x00);
      this.hmac.init(new SecretKeySpec(this.kBytes, algorithmName));
      this.hmac.update(this.vBytes);
      this.hmac.update((byte) 0x00);
      this.hmac.update(this.extendedKey);
    }
    catch (NoSuchAlgorithmException | InvalidKeyException ex) {
      throw new RuntimeException(ex);
    }
  }

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
      
      try {
        tracer.out().printfIndentln("this.modul.bitLength() = %d", this.modul.bitLength());
        
        do {
          byte[] nonceBytes = new byte[0];
          while (nonceBytes.length*8 < this.modul.bitLength()*2) {
            this.vBytes = this.hmac.doFinal(this.vBytes);
            int startIndex = nonceBytes.length;
            nonceBytes = Arrays.copyOf(nonceBytes, nonceBytes.length + this.vBytes.length);
            System.arraycopy(this.vBytes, 0, nonceBytes, startIndex, this.vBytes.length);
            
            tracer.out().printfIndentln("nonceBytes.length = %d", nonceBytes.length);
            
            if (nonceBytes.length*8 < this.modul.bitLength()) {
              this.hmac.update(vBytes);
              this.hmac.update((byte) 0x00);
              this.kBytes = this.hmac.doFinal();
              this.hmac.init(new SecretKeySpec(this.kBytes, ALGORITHM_NAME));
              this.vBytes = this.hmac.doFinal(this.vBytes);
            }
          }
          nonce = new BigInteger(1, nonceBytes).mod(this.modul);
          
          tracer.out().printfIndentln("nonce = %s", nonce);
          tracer.out().flush();
        } while (false);
        
        return nonce;
      }
      catch (InvalidKeyException ex) {
        throw new SignatureException(ex);
      }
    }
    finally {
      tracer.wayout();
    }
  }

  @Override
  public void copy(MessageDigest messageDigest) throws SignatureException {
    try {
      this.digestBytes = ((MessageDigest) messageDigest.clone()).digest();
      this.kBytes = this.hmac.doFinal(this.digestBytes);
      this.hmac.init(new SecretKeySpec(this.kBytes, ALGORITHM_NAME));
      this.vBytes = this.hmac.doFinal(this.vBytes);
      this.hmac.update(this.vBytes);
      this.hmac.update((byte) 0x01);
      this.hmac.update(this.extendedKey);
      this.kBytes = this.hmac.doFinal(this.digestBytes);
      this.hmac.init(new SecretKeySpec(this.kBytes, ALGORITHM_NAME));
      this.vBytes = this.hmac.doFinal(this.vBytes);
    }
    catch (CloneNotSupportedException | InvalidKeyException ex) {
      throw new SignatureException(ex);
    }
  }

  @Override
  public AbstractTracer getCurrentTracer() {
    return TracerFactory.getInstance().getDefaultTracer();
  }

}
