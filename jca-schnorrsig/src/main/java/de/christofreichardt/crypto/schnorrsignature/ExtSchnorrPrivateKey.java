package de.christofreichardt.crypto.schnorrsignature;

import java.math.BigInteger;
import java.util.Arrays;

public class ExtSchnorrPrivateKey extends SchnorrPrivateKey {
  private static final long serialVersionUID = 1L;
  
  final private byte[] extKeyBytes;

  public ExtSchnorrPrivateKey(SchnorrParams schnorrParams, BigInteger x, byte[] extKeyBytes) {
    super(schnorrParams, x);
    this.extKeyBytes = extKeyBytes;
  }

  public byte[] getExtKeyBytes() {
    return Arrays.copyOf(this.extKeyBytes, this.extKeyBytes.length);
  }

  @Override
  public String toString() {
    return "ExtSchnorrPrivateKey[x(" + this.x.bitLength() + ")=" + this.x + "]";
  }

}
