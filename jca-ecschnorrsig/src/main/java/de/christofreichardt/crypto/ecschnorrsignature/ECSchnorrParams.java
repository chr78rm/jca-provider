package de.christofreichardt.crypto.ecschnorrsignature;

import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesWithPrimeField.AffinePoint;

public class ECSchnorrParams {
  final private CurveSpec curveSpec;
  final private AffinePoint gPoint;
  
  public ECSchnorrParams(CurveSpec curveSpec, AffinePoint gPoint) {
    this.curveSpec = curveSpec;
    this.gPoint = gPoint;
  }

  public CurveSpec getCurveSpec() {
    return curveSpec;
  }

  public AffinePoint getgPoint() {
    return gPoint;
  }
}
