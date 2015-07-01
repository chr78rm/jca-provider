package de.christofreichardt.crypto.ecschnorrsignature;

import java.math.BigInteger;
import java.security.PrivateKey;

public class ECSchnorrPrivateKey extends ECSchnorrKey implements PrivateKey {
  private static final long serialVersionUID = 1L;
  private final BigInteger x;
  
  public ECSchnorrPrivateKey(ECSchnorrParams ecSchnorrParams, BigInteger x) {
    super(ecSchnorrParams);
    this.x = x;
  }

  @Override
  public String toString() {
    return "ECSchnorrPrivateKey[x=" + x +"]";
  }
}
