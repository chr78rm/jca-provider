package de.christofreichardt.crypto.ecschnorrsignature;

import java.math.BigInteger;

import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesOddCharacteristic.AffineCurve;

public class CurveGroup {
  private final AffineCurve curve;
  private final BigInteger order;
  private final BigInteger coFactor;
  
  public CurveGroup(AffineCurve curve, BigInteger order, BigInteger coFactor) {
    this.curve = curve;
    this.order = order;
    this.coFactor = coFactor;
  }

  public AffineCurve getCurve() {
    return curve;
  }

  public BigInteger getOrder() {
    return order;
  }

  public BigInteger getCoFactor() {
    return coFactor;
  }
}
