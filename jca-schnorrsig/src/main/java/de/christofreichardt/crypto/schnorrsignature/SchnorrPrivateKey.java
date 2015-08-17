/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package de.christofreichardt.crypto.schnorrsignature;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Arrays;

/**
 * This class represents the private key of the Schnorr signature scheme.
 * 
 * @author Christof Reichardt
 */
public class SchnorrPrivateKey extends SchnorrKey implements PrivateKey {
  private static final long serialVersionUID = 1L;
  
  protected final BigInteger x;
  final private byte[] extKeyBytes;
  
  /**
   * Creates a private key for the Schnorr signature scheme.
   * 
   * @param schnorrParams the domain parameter
   * @param x the actual private key
   */
  public SchnorrPrivateKey(SchnorrParams schnorrParams, BigInteger x) {
    super(schnorrParams);
    this.x = x;
    this.extKeyBytes = null;
  }
  
  /**
   * Creates a private key for the Schnorr signature scheme together with some extra key bytes.
   * 
   * @param schnorrParams the domain parameter
   * @param x the actual private key
   * @param extKeyBytes the extra key bytes
   */
  public SchnorrPrivateKey(SchnorrParams schnorrParams, BigInteger x, byte[] extKeyBytes) {
    super(schnorrParams);
    this.x = x;
    this.extKeyBytes = extKeyBytes;
  }

  public BigInteger getX() {
    return x;
  }

  @Override
  public byte[] getEncoded() {
    throw new UnsupportedOperationException("Not supported yet.");
  }

  public byte[] getExtKeyBytes() {
    return this.extKeyBytes != null ? Arrays.copyOf(this.extKeyBytes, this.extKeyBytes.length) : null;
  }

  @Override
  public String toString() {
    return "SchnorrPrivateKey[x(" + this.x.bitLength() + ")=" + this.x + "]";
  }

}
