package de.christofreichardt.crypto.ecschnorrsignature;

import java.security.spec.AlgorithmParameterSpec;

import de.christofreichardt.crypto.AlmostUniformRandomNonceGenerator;
import de.christofreichardt.crypto.NonceGenerator;

public class ECSchnorrSigParameterSpec implements AlgorithmParameterSpec {
  public enum PointMultiplicationStrategy {UNKNOWN_POINT, FIXED_POINT}
  
  final private PointMultiplicationStrategy pointMultiplicationStrategy;
  final private NonceGenerator nonceGenerator;

  public ECSchnorrSigParameterSpec() {
    this.pointMultiplicationStrategy = PointMultiplicationStrategy.UNKNOWN_POINT;
    this.nonceGenerator = new AlmostUniformRandomNonceGenerator();
  }

  public ECSchnorrSigParameterSpec(PointMultiplicationStrategy pointMultiplicationStrategy) {
    this.pointMultiplicationStrategy = pointMultiplicationStrategy;
    this.nonceGenerator = new AlmostUniformRandomNonceGenerator();
  }

  public ECSchnorrSigParameterSpec(PointMultiplicationStrategy pointMultiplicationStrategy, NonceGenerator nonceGenerator) {
    this.pointMultiplicationStrategy = pointMultiplicationStrategy;
    this.nonceGenerator = nonceGenerator;
  }
  
  public ECSchnorrSigParameterSpec(NonceGenerator nonceGenerator) {
    this.pointMultiplicationStrategy = PointMultiplicationStrategy.UNKNOWN_POINT;
    this.nonceGenerator = nonceGenerator;
  }

  public PointMultiplicationStrategy getPointMultiplicationStrategy() {
    return pointMultiplicationStrategy;
  }

  public NonceGenerator getNonceGenerator() {
    return nonceGenerator;
  }
  
}
