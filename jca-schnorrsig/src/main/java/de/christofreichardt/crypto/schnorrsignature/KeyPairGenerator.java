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
  
  private SchnorrSigGenParameterSpec schnorrSigGenParameterSpec;
  private SecureRandom secureRandom = new SecureRandom();

  /**
   * Instantiates a (Schnorr) KeyPairGenerator object with default parameter.
   */
  public KeyPairGenerator() {
    try {
      this.schnorrSigGenParameterSpec = new SchnorrSigGenParameterSpec(SchnorrSigGenParameterSpec.Strength.DEFAULT);
    }
    catch (InvalidAlgorithmParameterException ex) {
      assert false;
    }
  }
  
  /**
   * Initialises the {@link KeyPairGenerator KeyPairGenerator} with the given arguments.
   * 
   * @param algorithmParameterSpec expected to be an instance of {@link SchnorrSigGenParameterSpec SchnorrSigGenParameterSpec}, otherwise an 
   * {@link InvalidAlgorithmParameterException InvalidAlgorithmParameterException} will be thrown. 
   * @param secureRandom specifies a source of randomness.
   * @throws InvalidAlgorithmParameterException if algorithmParameterSpec isn't a SchnorrSigGenParameterSpec instance.
   */
  @Override
   public void initialize(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "initialize(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom)");
    
    try {
      if (!(algorithmParameterSpec instanceof SchnorrSigGenParameterSpec))
        throw new InvalidAlgorithmParameterException("Need a 'SchnorrSigGenParameterSpec'.");
      
      this.schnorrSigGenParameterSpec = (SchnorrSigGenParameterSpec) algorithmParameterSpec;
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
        this.schnorrSigGenParameterSpec = new SchnorrSigGenParameterSpec(keysize, keysize / 4);
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
   * with a {@link SchnorrSigGenParameterSpec SchnorrSigGenParameterSpec} indicating custom strength.
   * 
   * @return the generated key pair consisting of a {@link SchnorrPublicKey SchnorrPublicKey} and a {@link SchnorrPrivateKey SchnorrPrivateKey}
   */
  @Override
  public KeyPair generateKeyPair() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("KeyPair", this, "generateKeyPair()");
    
    try {
      BigInteger p,q;
      if (this.schnorrSigGenParameterSpec.getStrength() != SchnorrSigGenParameterSpec.Strength.CUSTOM) {
        SchnorrGroup schnorrGroup = selectPrecomputedGroup();
        p = schnorrGroup.getP();
        q = schnorrGroup.getQ();
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
            if (this.secureRandom.nextInt(this.schnorrSigGenParameterSpec.getL()) == 0) {
              groupFound = false;
              break;
            }
          } while(!p.isProbablePrime(CERTAINTY)  ||  
              (p.bitLength() != this.schnorrSigGenParameterSpec.getL()  &&  this.schnorrSigGenParameterSpec.isExact()));
        } while(!groupFound);
      }
      
      tracer.out().printfIndentln("p(%d) = %d", p.bitLength(), p);
      
      BigInteger g;
      do {
        BigInteger r;
        do {
          r = new BigInteger(this.schnorrSigGenParameterSpec.getL()*2, this.secureRandom).mod(p);
        } while (r.equals(BigInteger.ZERO));
        g = r.modPow((p.subtract(BigInteger.ONE)).divide(q), p);
      } while (g.equals(BigInteger.ONE));
      
      tracer.out().printfIndentln("g(%d) = %d", g.bitLength(), g);
      
      BigInteger x, h;
      do {
        x = new BigInteger(this.schnorrSigGenParameterSpec.getT()*2, secureRandom).mod(q);
      } while(x.equals(BigInteger.ZERO));
      h = g.modPow(x, p);
      
      tracer.out().printfIndentln("x(%d) = %d", x.bitLength(), x);
      tracer.out().printfIndentln("y(%d) = %d", h.bitLength(), h);
      
      SchnorrGroup schnorrGroup = new SchnorrGroup(p, q);
//      SchnorrParams schnorrParams = new SchnorrParams(p, q, g);
      SchnorrParams schnorrParams = new SchnorrParams(schnorrGroup, g);
      SchnorrPrivateKey schnorrPrivateKey = new SchnorrPrivateKey(schnorrParams, x);
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
      if (this.schnorrSigGenParameterSpec.getStrength() != SchnorrSigGenParameterSpec.Strength.DEFAULT)
        throw new UnsupportedOperationException("Not implemented yet.");
      
      return SchnorrGroups.DEFAULT[this.secureRandom.nextInt(SchnorrGroups.DEFAULT.length)];
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