package de.christofreichardt.crypto.schnorrsignature;

import java.security.spec.AlgorithmParameterSpec;

public class SchnorrSigParameterSpec implements AlgorithmParameterSpec {
  final private NonceGenerator nonceGenerator;

  public SchnorrSigParameterSpec() {
    this.nonceGenerator = new AlmostUniformRandomNonceGenerator();
  }
  
  public SchnorrSigParameterSpec(NonceGenerator nonceGenerator) {
    this.nonceGenerator = nonceGenerator;
  }

  public NonceGenerator getNonceGenerator() {
    return nonceGenerator;
  }
}
