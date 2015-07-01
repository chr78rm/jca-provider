package de.christofreichardt.crypto.ecschnorrsignature;

import java.security.PublicKey;

import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesOddCharacteristic.AffinePoint;

public class ECSchnorrPublicKey extends ECSchnorrKey implements PublicKey {
  private static final long serialVersionUID = 1L;
  private final AffinePoint hPoint;
  
  public ECSchnorrPublicKey(ECSchnorrParams ecSchnorrParams, AffinePoint hPoint) {
    super(ecSchnorrParams);
    this.hPoint = hPoint;
  }

  @Override
  public String toString() {
    return "ECSchnorrPublicKey[hPoint=" + hPoint + "]";
  }
}
