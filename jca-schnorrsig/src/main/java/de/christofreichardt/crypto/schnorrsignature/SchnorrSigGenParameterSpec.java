/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package de.christofreichardt.crypto.schnorrsignature;

import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

/**
 * This class encapsulates the security parameter for the Schnorr signature scheme.
 * 
 * @author Christof Reichardt
 */
public class SchnorrSigGenParameterSpec implements AlgorithmParameterSpec {
  final public static int L_MINIMAL = 1024;
  final public static int T_MINIMAL = 160;
  final public static int L = 2048;
  final public static int T = 512;
  final public static int L_STRONG = 4096;
  final public static int T_STRONG = 1024;
  public enum Strength {MINIMAL, DEFAULT, STRONG, CUSTOM};
  
  final private Strength strength;
  final private int l,t;
  private final boolean exact;

  /**
   * Expects the security parameter which roughly define the bit length of p,q.
   * 
   * @param l defines the bit length of p.
   * @param t defines the bit length of q.
   * @throws InvalidAlgorithmParameterException if some constraints don't hold, e.g. l must not be smaller than 1024.
   */
  public SchnorrSigGenParameterSpec(int l, int t) throws InvalidAlgorithmParameterException {
    this(l, t, false);
  }

  /**
   * Expects the security parameter which roughly define the bit length of p,q.
   * 
   * @param l defines the bit length of p.
   * @param t defines the bit length of q.
   * @param exact indicates if the above requirements should be met exactly.
   * @throws InvalidAlgorithmParameterException if some constraints don't hold, e.g. l must not be smaller than 1024.
   */
  public SchnorrSigGenParameterSpec(int l, int t, boolean exact) throws InvalidAlgorithmParameterException {
    this.l = l;
    this.t = t;
    this.strength = Strength.CUSTOM;
    this.exact = exact;
    validate();
  }

  /**
   * Expects a qualifier which indicates the desired {@link Strength Strength} of the Signature scheme.
   * 
   * @param strength the qualifier
   * @throws InvalidAlgorithmParameterException indicates an illegal qualifier.
   */
  public SchnorrSigGenParameterSpec(Strength strength) throws InvalidAlgorithmParameterException {
    this.strength = strength;
    switch (this.strength) {
      case CUSTOM:
        throw new IllegalArgumentException("This constructor doesn't evaluate custom security parameters.");
      case MINIMAL:
        this.l = L_MINIMAL;
        this.t = T_MINIMAL;
        break;
      case DEFAULT:
        this.l = L;
        this.t = T;
        break;
      case STRONG:
        this.l = L_STRONG;
        this.t = T_STRONG;
        break;
      default:
        throw new IllegalArgumentException("Unknown strength.");
    }
    this.exact = false;
    validate();
  }
  
  private void validate() throws InvalidAlgorithmParameterException {
    if (this.l < 1024  ||  this.t < 160)
      throw new InvalidAlgorithmParameterException("Insufficient security parameter.");
    if (this.l < this.t)
      throw new InvalidAlgorithmParameterException("Invalid security parameter.");
  }

  public int getL() {
    return this.l;
  }

  public int getT() {
    return this.t;
  }

  public Strength getStrength() {
    return strength;
  }

  public boolean isExact() {
    return exact;
  }

  @Override
  public String toString() {
    return "SchnorrSigGenParameterSpec[" + "l=" + l + ", t=" + t + "]";
  }
}
