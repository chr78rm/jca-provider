package de.christofreichardt.crypto.ecschnorrsignature;

import java.security.spec.AlgorithmParameterSpec;

public class ECSchnorrSigParameterSpec implements AlgorithmParameterSpec {
  public enum PointMultiplicationStrategy {UNKNOWN_POINT, FIXED_POINT}
  
  final private PointMultiplicationStrategy pointMultiplicationStrategy;

  public ECSchnorrSigParameterSpec() {
    this.pointMultiplicationStrategy = PointMultiplicationStrategy.UNKNOWN_POINT;
  }

  public ECSchnorrSigParameterSpec(PointMultiplicationStrategy pointMultiplicationStrategy) {
    this.pointMultiplicationStrategy = pointMultiplicationStrategy;
  }

  public PointMultiplicationStrategy getPointMultiplicationStrategy() {
    return pointMultiplicationStrategy;
  }
  
}
