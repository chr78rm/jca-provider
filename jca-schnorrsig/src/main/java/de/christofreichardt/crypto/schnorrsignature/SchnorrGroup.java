/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package de.christofreichardt.crypto.schnorrsignature;

import java.math.BigInteger;

/**
 * A data representation for Schnorr groups, that is to say q | (p - 1) holds and p,q are prime.
 * 
 * @author Christof Reichardt
 */
public class SchnorrGroup {
  final private BigInteger p;
  final private BigInteger q;

  /**
   * Expects two primes p,q such that q | (p - 1) holds.
   * 
   * @param p the prime defining the main group.
   * @param q the prime defining the subgroup.
   */
  public SchnorrGroup(BigInteger p, BigInteger q) {
    this.p = p;
    this.q = q;
    if (this.p.subtract(BigInteger.ONE).mod(this.q) != BigInteger.ZERO  ||  
        !this.p.isProbablePrime(KeyPairGenerator.CERTAINTY)  ||  !this.q.isProbablePrime(KeyPairGenerator.CERTAINTY))
      throw new IllegalArgumentException("Not a Schnorr group.");
  }

  public BigInteger getP() {
    return p;
  }

  public BigInteger getQ() {
    return q;
  }

  @Override
  public String toString() {
    return "SchnorrGroup[" + "p(" + p.bitLength() + ")=" + p + ", q(" + q.bitLength() + ")=" + q + "]";
  }
}
