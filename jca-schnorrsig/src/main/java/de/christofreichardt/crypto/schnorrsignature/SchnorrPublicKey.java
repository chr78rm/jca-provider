/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package de.christofreichardt.crypto.schnorrsignature;

import java.math.BigInteger;
import java.security.PublicKey;

/**
 * This class represents the public key of the Schnorr signature scheme.
 * 
 * @author Christof Reichardt
 */
public class SchnorrPublicKey extends SchnorrKey implements PublicKey {
  private static final long serialVersionUID = 1L;
  private final BigInteger h;
  
  /**
   * Creates a public key for the Schnorr signature scheme.
   * 
   * @param schnorrParams the domain parameter
   * @param h the actual public key
   */
  public SchnorrPublicKey(SchnorrParams schnorrParams, BigInteger h) {
    super(schnorrParams);
    this.h = h;
  }

  public BigInteger getH() {
    return h;
  }

  @Override
  public byte[] getEncoded() {
    throw new UnsupportedOperationException("Not supported yet.");
  }
  
  @Override
  public String toString() {
    return "SchnorrPublicKey[y(" + h.bitLength() + ")=" + this.h + "]";
  }
}
