package de.christofreichardt.crypto.schnorrsignature;

import java.security.spec.AlgorithmParameterSpec;

public class SchnorrSigParameterSpec implements AlgorithmParameterSpec {
  public enum NonceGeneratorStrategy {SECURE_RANDOM, PRIVATEKEY_MSG_HASH}
  
  final private NonceGeneratorStrategy nonceGeneratorStrategy;

  public SchnorrSigParameterSpec() {
    this.nonceGeneratorStrategy = NonceGeneratorStrategy.SECURE_RANDOM;
  }

  public SchnorrSigParameterSpec(NonceGeneratorStrategy nonceGeneratorStrategy) {
    this.nonceGeneratorStrategy = nonceGeneratorStrategy;
  }

  public NonceGeneratorStrategy getNonceGeneratorStrategy() {
    return nonceGeneratorStrategy;
  }
}
