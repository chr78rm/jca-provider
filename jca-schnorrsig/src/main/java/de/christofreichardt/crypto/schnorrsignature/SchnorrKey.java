/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package de.christofreichardt.crypto.schnorrsignature;

import java.security.Key;

/**
 * The base class of a {@link SchnorrPrivateKey SchnorrPrivateKey} and a {@link SchnorrPublicKey SchnorrPublicKey}.
 * 
 * @author Christof Reichardt
 */
public abstract class SchnorrKey implements Key {
  private static final long serialVersionUID = 1L;
  final private SchnorrParams schnorrParams;

  /**
   * Expects the (public) domain parameter of the Schnorr signature scheme.
   * 
   * @param schnorrParams the domain parameter
   */
  public SchnorrKey(SchnorrParams schnorrParams) {
    this.schnorrParams = schnorrParams;
  }

  @Override
  public String getAlgorithm() {
    return "SchnorrSignature";
  }

  @Override
  public String getFormat() {
    return "XML";
  }

//  @Override
//  public byte[] getEncoded() {
//    throw new UnsupportedOperationException("Not supported yet.");
//  }

  public SchnorrParams getSchnorrParams() {
    return this.schnorrParams;
  }

}
