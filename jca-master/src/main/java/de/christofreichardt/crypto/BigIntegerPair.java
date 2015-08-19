package de.christofreichardt.crypto;

import java.math.BigInteger;
import java.util.Arrays;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;

/**
 * This class encapsulates the two BigInteger values which make up the actual Schnorr Signature. It provides
 * conversion methods to transform the pair into a byte array and vice versa.
 * 
 * @author Christof Reichardt
 */
public class BigIntegerPair implements Traceable {
  final private BigInteger e;
  final private BigInteger y;
  final private byte[] eBytes;
  final private byte[] yBytes;
  
  /**
   * Constructs a pair with the given arguments.
   * 
   * @param e e \u2261 H(M \u2016 s)
   * @param y y \u2261 r + ex
   */
  public BigIntegerPair(BigInteger e, BigInteger y) {
    this.e = e;
    this.eBytes = e.toByteArray();
    if (this.eBytes.length > 255)
      throw new IllegalArgumentException("Accept maximal 255 e-bytes.");
    this.y = y;
    this.yBytes = y.toByteArray();
  }
  
  /**
   * Constructs a pair by decoding the given byte array.
   * 
   * @param bytes the byte array which encodes the two BigInteger values
   */
  public BigIntegerPair(byte[] bytes) {
    int eSize = bytes[0] & 255;
    this.eBytes = Arrays.copyOfRange(bytes, 1, 1 + eSize);
    this.e = new BigInteger(1, this.eBytes);
    this.yBytes = Arrays.copyOfRange(bytes, 1 + eSize, bytes.length);
    this.y = new BigInteger(1, this.yBytes);
  }

  public BigInteger getE() {
    return e;
  }

  public BigInteger getY() {
    return y;
  }
  
  /**
   * Converts the two BigInteger values into a byte array. The first byte contains the number of
   * e bytes.
   * 
   * @return a byte array encoding the two BigInteger values.
   */
  public byte[] toByteArray() {
    byte[] bytes = new byte[1 + this.eBytes.length + this.yBytes.length];
    bytes[0] = (byte) this.eBytes.length;
    System.arraycopy(this.eBytes, 0, bytes, 1, this.eBytes.length);
    System.arraycopy(this.yBytes, 0, bytes, 1 + this.eBytes.length, this.yBytes.length);
    
    return bytes;
  }
  
  /**
   * For internal use only.
   */
  public void trace() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "trace()");
    
    try {
      tracer.out().printfIndentln("e(%d) = %d", this.e.bitLength(), this.e);
      tracer.out().printfIndentln("--- eBytes(%d) ---", this.eBytes.length);
      traceBytes(this.eBytes);
      tracer.out().printfIndentln("y(%d) = %d", this.y.bitLength(), this.y);
      tracer.out().printfIndentln("--- yBytes(%d) ---", this.yBytes.length);
      traceBytes(this.yBytes);
    }
    finally {
      tracer.wayout();
    }
  }
  
  private void traceBytes(byte[] bytes) {
    AbstractTracer tracer = getCurrentTracer();
    for (int i=0; i<bytes.length; i++) {
      if (i % 16 == 0) {
        if (i != 0)
          tracer.out().println();
        tracer.out().printIndentString();
      }
      tracer.out().printf("%3d ", bytes[i] & 255);
    }
    tracer.out().println();
  }

  @Override
  public AbstractTracer getCurrentTracer() {
    return TracerFactory.getInstance().getCurrentPoolTracer();
  }
}
