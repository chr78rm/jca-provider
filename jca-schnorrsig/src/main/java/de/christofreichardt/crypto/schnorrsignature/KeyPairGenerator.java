/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package de.christofreichardt.crypto.schnorrsignature;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * This class is an implementation of the Service Provider Interface (SPI) for generating key pairs as defined by the 
 * <a href="http://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html">Java Cryptography Architecture (JCA)</a>.
 * The generated key pairs shall be used in combination with the Schnorr signatur scheme which is based upon the Discrete Logarithm (DL) problem. In addition
 * to the key pairs the DL domain parameter corresponding to a <a href="http://en.wikipedia.org/wiki/Schnorr_group">Schnorr group</a> can be generated if required. 
 * The creation of the DL domain parameter and the key pairs are very similar to the creation of the analogous parameter of the Digital Signature Algorithm (DSA). 
 * In fact, the National Institute of Standards (NIST) has copied this from Schnorrs Signature scheme proposal.
 * 
 * @author Christof Reichardt
 */
public class KeyPairGenerator extends KeyPairGeneratorSpi implements Traceable {
  
  /**
   * The probability that prime numbers generated by the {@link KeyPairGenerator KeyPairGenerator} are in fact prime 
   * exceeds <span style="white-space: nowrap">(1 - 1/2<sup>CERTAINTY</sup>)</span>.
   */
  final public static int CERTAINTY = 100;
  
  /**
   * Defines the number of extra secret key bytes
   */
  final public static int EXT_KEYBYTES = 8;
  
  private SchnorrSigKeyGenParameterSpec schnorrSigGenParameterSpec;
  private SecureRandom secureRandom = new SecureRandom();

  /**
   * Instantiates a (Schnorr) KeyPairGenerator object with default parameter.
   */
  public KeyPairGenerator() {
    try {
      this.schnorrSigGenParameterSpec = new SchnorrSigKeyGenParameterSpec(SchnorrSigKeyGenParameterSpec.Strength.DEFAULT);
    }
    catch (InvalidAlgorithmParameterException ex) {
      assert false;
    }
  }
  
  /**
   * Initialises the {@link KeyPairGenerator KeyPairGenerator} with the given arguments.
   * 
   * @param algorithmParameterSpec expected to be an instance of {@link SchnorrSigKeyGenParameterSpec SchnorrSigKeyGenParameterSpec}, otherwise an 
   * {@link InvalidAlgorithmParameterException InvalidAlgorithmParameterException} will be thrown. 
   * @param secureRandom specifies a source of randomness.
   * @throws InvalidAlgorithmParameterException if algorithmParameterSpec isn't a SchnorrSigKeyGenParameterSpec instance.
   */
  @Override
   public void initialize(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "initialize(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom)");
    
    try {
      if (!(algorithmParameterSpec instanceof SchnorrSigKeyGenParameterSpec))
        throw new InvalidAlgorithmParameterException("Need a 'SchnorrSigKeyGenParameterSpec'.");
      
      this.schnorrSigGenParameterSpec = (SchnorrSigKeyGenParameterSpec) algorithmParameterSpec;
      this.secureRandom = secureRandom;
      
      traceParameter();
    }
    finally {
      tracer.wayout();
    }
  }

  /**
   * Initialises the {@link KeyPairGenerator KeyPairGenerator} with the given arguments.
   * 
   * @param keysize specifies the size of the to be used <a href="http://en.wikipedia.org/wiki/Schnorr_group">Schnorr group</a>.
   * @param secureRandom specifies a source of randomness.
   */
  @Override
  public void initialize(int keysize, SecureRandom secureRandom) {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "initialize(int keysize, SecureRandom secureRandom)");

    try {
      try {
        this.schnorrSigGenParameterSpec = new SchnorrSigKeyGenParameterSpec(keysize, keysize / 4);
        this.secureRandom = secureRandom;

        traceParameter();
      }
      catch (InvalidAlgorithmParameterException ex) {
        throw new InvalidParameterException(ex.getMessage());
      }
    }
    finally {
      tracer.wayout();
    }
  }

  /**
   * Generates the key pair. The DL domain parameter will be created as well if the {@link KeyPairGenerator KeyPairGenerator} has been initialized
   * with a {@link SchnorrSigKeyGenParameterSpec SchnorrSigKeyGenParameterSpec} indicating custom strength.
   * 
   * @return the generated key pair consisting of a {@link SchnorrPublicKey SchnorrPublicKey} and a {@link SchnorrPrivateKey SchnorrPrivateKey}
   */
  @Override
  public KeyPair generateKeyPair() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("KeyPair", this, "generateKeyPair()");
    
    try {
      BigInteger p,q;
      if (this.schnorrSigGenParameterSpec.getStrength() != SchnorrSigKeyGenParameterSpec.Strength.CUSTOM) {
        SchnorrGroup schnorrGroup = selectPrecomputedGroup();
        p = schnorrGroup.getP();
        q = schnorrGroup.getQ();
        
        tracer.out().printfIndentln("q(%d) = %d", q.bitLength(), q);
        tracer.out().printfIndentln("p(%d) = %d", p.bitLength(), p);
      }
      else {
        boolean groupFound;
        do {
          groupFound = true;
          q = BigInteger.probablePrime(this.schnorrSigGenParameterSpec.getT(), this.secureRandom);
      
          tracer.out().printfIndentln("q(%d) = %d", q.bitLength(), q);
          tracer.out().flush();
          
          int bitDiff = this.schnorrSigGenParameterSpec.getL() - this.schnorrSigGenParameterSpec.getT();
          do {
            BigInteger r = new BigInteger(bitDiff, this.secureRandom);
            p = q.multiply(r).add(BigInteger.ONE);
            if (this.schnorrSigGenParameterSpec.isExact() && p.bitLength() != this.schnorrSigGenParameterSpec.getL())
              continue;
            if (p.isProbablePrime(CERTAINTY))
              break;
            if (this.secureRandom.nextInt(this.schnorrSigGenParameterSpec.getL()) < this.schnorrSigGenParameterSpec.getL()/1000) {
              groupFound = false;
              break;
            }
          } while(true);
        } while(!groupFound);
        
        tracer.out().printfIndentln("p(%d) = %d", p.bitLength(), p);
      }
      
      BigInteger g;
      do {
        BigInteger r;
        do {
          r = new BigInteger(this.schnorrSigGenParameterSpec.getL()*2, this.secureRandom).mod(p);
        } while (r.equals(BigInteger.ZERO));
        g = r.modPow((p.subtract(BigInteger.ONE)).divide(q), p);
      } while (g.equals(BigInteger.ONE));
      
      tracer.out().printfIndentln("g(%d) = %d", g.bitLength(), g);
      assert g.modPow(q, p).equals(BigInteger.ONE);
      
      BigInteger x, h;
      do {
        x = new BigInteger(this.schnorrSigGenParameterSpec.getT()*2, secureRandom).mod(q);
      } while(x.equals(BigInteger.ZERO));
      h = g.modPow(x, p);
      
      tracer.out().printfIndentln("x(%d) = %d", x.bitLength(), x);
      tracer.out().printfIndentln("h(%d) = %d", h.bitLength(), h);
      
      SchnorrGroup schnorrGroup = new SchnorrGroup(p, q);
      SchnorrParams schnorrParams = new SchnorrParams(schnorrGroup, g);
      SchnorrPrivateKey schnorrPrivateKey;
      if (this.schnorrSigGenParameterSpec.isExtended()) {
        byte[] extraKeyBytes = new byte[EXT_KEYBYTES];
        this.secureRandom.nextBytes(extraKeyBytes);
        schnorrPrivateKey = new SchnorrPrivateKey(schnorrParams, x, extraKeyBytes);
        
        tracer.out().printfIndentln("Generated an ExtSchnorrPrivateKey ...");
      }
      else
        schnorrPrivateKey = new SchnorrPrivateKey(schnorrParams, x);
      SchnorrPublicKey schnorrPublicKey = new SchnorrPublicKey(schnorrParams, h);
      
      return new KeyPair(schnorrPublicKey, schnorrPrivateKey);
    }
    finally {
      tracer.wayout();
    }
  }
  
  private SchnorrGroup selectPrecomputedGroup() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("SchnorrGroup", this, "selectPrecomputedGroup()");
    
    try {
      SchnorrGroup schnorrGroup;
      switch (this.schnorrSigGenParameterSpec.getStrength()) {
      case DEFAULT:
        schnorrGroup = SchnorrGroups.DEFAULT[this.secureRandom.nextInt(SchnorrGroups.DEFAULT.length)];
        break;
      case MINIMAL:
        schnorrGroup = SchnorrGroups.MINIMAL[this.secureRandom.nextInt(SchnorrGroups.MINIMAL.length)];
        break;
      case STRONG:
        schnorrGroup = SchnorrGroups.STRONG[this.secureRandom.nextInt(SchnorrGroups.STRONG.length)];
        break;
      case CUSTOM:
        throw new IllegalStateException("Not allowed here.");
      default:
        throw new UnsupportedOperationException("Unknown strength.");
      }
      
      return schnorrGroup;
    }
    finally {
      tracer.wayout();
    }
  }
  
  private void traceParameter() throws InvalidAlgorithmParameterException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "traceParameter()");
    
    try {
      tracer.out().printfIndentln("this.schnorrSigGenParameterSpec = %s", this.schnorrSigGenParameterSpec);
      tracer.out().printfIndentln("this.secureRandom.getProvider() = %s", this.secureRandom.getProvider());
      tracer.out().printfIndentln("this.secureRandom.getAlgorithm() = %s", this.secureRandom.getAlgorithm());
    }
    finally {
      tracer.wayout();
    }
  }

  @Override
  public AbstractTracer getCurrentTracer() {
    return TracerFactory.getInstance().getCurrentPoolTracer();
  }

}
