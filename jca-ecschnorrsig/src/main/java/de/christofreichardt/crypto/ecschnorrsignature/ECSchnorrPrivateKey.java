package de.christofreichardt.crypto.ecschnorrsignature;

import java.math.BigInteger;
import java.security.PrivateKey;

public class ECSchnorrPrivateKey extends ECSchnorrKey implements PrivateKey {
  private static final long serialVersionUID = 1L;
  private final BigInteger x;
  final private byte[] extKeyBytes;
  
  public ECSchnorrPrivateKey(ECSchnorrParams ecSchnorrParams, BigInteger x) {
    this(ecSchnorrParams, x, null);
  }

  public ECSchnorrPrivateKey(ECSchnorrParams ecSchnorrParams, BigInteger x, byte[] extKeyBytes) {
    super(ecSchnorrParams);
    this.x = x;
    this.extKeyBytes = extKeyBytes;
  }

  public BigInteger getX() {
    return x;
  }

  public byte[] getExtKeyBytes() {
    return extKeyBytes;
  }

  @Override
  public String toString() {
    return "ECSchnorrPrivateKey[x=" + x +"]";
  }
}
