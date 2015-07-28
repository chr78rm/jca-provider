package de.christofreichardt.crypto.ecschnorrsignature;

import java.math.BigInteger;

import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesWithPrimeField.AffineCurve;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesWithPrimeField.AffinePoint;

public class CurveSpec {
  private final AffineCurve curve;
  private final BigInteger order;
  private final BigInteger coFactor;
  private final AffinePoint gPoint;
  
  public CurveSpec(AffineCurve curve, BigInteger order, BigInteger coFactor, AffinePoint gPoint) {
    this.curve = curve;
    this.order = order;
    this.coFactor = coFactor;
    this.gPoint = gPoint;
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

  public AffinePoint getgPoint() {
    return gPoint;
  }
}
