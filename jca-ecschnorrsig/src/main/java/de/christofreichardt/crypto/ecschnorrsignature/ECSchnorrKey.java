package de.christofreichardt.crypto.ecschnorrsignature;

import java.security.Key;

public class ECSchnorrKey implements Key {
  private static final long serialVersionUID = 1L;
  private final ECSchnorrParams ecSchnorrParams;

  public ECSchnorrKey(ECSchnorrParams ecSchnorrParams) {
    super();
    this.ecSchnorrParams = ecSchnorrParams;
  }
  
  public ECSchnorrParams getEcSchnorrParams() {
    return this.ecSchnorrParams;
  }

  @Override
  public String getAlgorithm() {
    return "ECSchnorrSignature";
  }

  @Override
  public byte[] getEncoded() {
    return null;
  }

  @Override
  public String getFormat() {
    return null;
  }

}
