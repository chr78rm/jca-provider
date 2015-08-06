package de.christofreichardt.crypto.schnorrsignature;

import java.math.BigInteger;
import java.util.Arrays;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;

public class BigIntegerPair implements Traceable {
  final private BigInteger e;
  final private BigInteger y;
  final private byte[] eBytes;
  final private byte[] yBytes;
  
  public BigIntegerPair(BigInteger e, BigInteger y) {
    this.e = e;
    this.eBytes = e.toByteArray();
    if (this.eBytes.length > 255)
      throw new IllegalArgumentException("Accept maximal 255 e-bytes.");
    this.y = y;
    this.yBytes = y.toByteArray();
  }
  
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
  
  public byte[] toByteArray() {
    byte[] bytes = new byte[1 + this.eBytes.length + this.yBytes.length];
    bytes[0] = (byte) this.eBytes.length;
    System.arraycopy(this.eBytes, 0, bytes, 1, this.eBytes.length);
    System.arraycopy(this.yBytes, 0, bytes, 1 + this.eBytes.length, this.yBytes.length);
    
    return bytes;
  }
  
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
