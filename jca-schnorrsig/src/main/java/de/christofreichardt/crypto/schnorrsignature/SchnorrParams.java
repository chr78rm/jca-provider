/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package de.christofreichardt.crypto.schnorrsignature;

import java.math.BigInteger;

/**
 * The public domain parameter of the Schnorr signature scheme.
 * 
 * @author Christof Reichardt
 */
public class SchnorrParams {
  private final BigInteger p,q,g;

  /**
   * Creates a SchnorrParams object with the given domain parameter.
   * 
   * @param p the prime defining the main group.
   * @param q the prime defining the subgroup.
   * @param g a generator within the subgroup.
   */
  public SchnorrParams(BigInteger p, BigInteger q, BigInteger g) {
    this.p = p;
    this.q = q;
    if (this.p.subtract(BigInteger.ONE).mod(this.q) != BigInteger.ZERO  ||  
        !this.p.isProbablePrime(KeyPairGenerator.CERTAINTY)  ||  !this.q.isProbablePrime(KeyPairGenerator.CERTAINTY))
      throw new IllegalArgumentException("Not a Schnorr group.");
    this.g = g;
  }
  
  /**
   * Creates a SchnorrParams object with the given domain parameter.
   * 
   * @param schnorrGroup a data object defining a <a href="http://en.wikipedia.org/wiki/Schnorr_group">Schnorr group</a>.
   * @param g a generator within the group.
   */
  public SchnorrParams(SchnorrGroup schnorrGroup, BigInteger g) {
    this.p = schnorrGroup.getP();
    this.q = schnorrGroup.getQ();
    this.g = g;
    if (!this.g.modPow(this.q, this.p).equals(BigInteger.ONE))
      throw new IllegalArgumentException("Invalid generator.");
  }

  public BigInteger getP() {
    return p;
  }

  public BigInteger getQ() {
    return q;
  }

  public BigInteger getG() {
    return g;
  }

  @Override
  public String toString() {
    return "SchnorrParams[p(" + this.p.bitLength() + ")=" + this.p + ", q(" + this.q.bitLength() + ")=" + this.q + ", g(" + this.g.bitLength() + ")=" + this.g + "]";
  }
}
