/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package de.christofreichardt.crypto.schnorrsignature;

import de.christofreichardt.crypto.schnorrsignature.SchnorrSigParameterSpec.NonceGeneratorStrategy;
import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.LogLevel;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * <p>
 * This class is an implementation of the Service Provider Interface (SPI) for generating digital signatures as defined by the 
 * <a href="http://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html">Java Cryptography Architecture (JCA)</a>.
 * It implements the Schnorr Signature scheme based on <a href="http://en.wikipedia.org/wiki/Schnorr_group">Schnorr groups</a>.
 * </p>
 * <table summary="">
 *  <tbody>
 *    <tr>
 *      <td style="font-weight: bold">Public domain parameter</td>
 *      <td style="padding-left: 20px">g, G = \u27E8g\u27E9, |G| = q, p = qr + 1, p prime, q prime, H: {0,1}<sup>*</sup> \u2192 \u2124<sub>q</sub></td>
 *    </tr>
 *    <tr>
 *      <td style="font-weight: bold">Secret key</td>
 *      <td style="padding-left: 20px"> x \u2208<sub>R</sub> (\u2124<sub>q</sub>)<sup>\u00D7</sup></td>
 *    </tr>
 *    <tr>
 *      <td style="font-weight: bold">Public key</td>
 *      <td style="padding-left: 20px">h \u2261<sub>p</sub> g<sup>x</sup></td>
 *    </tr>
 *    <tr>
 *      <td style="font-weight: bold">Signing M\u2208{0,1}<sup>*</sup></td>
 *      <td style="padding-left: 20px">
 *        r \u2208<sub>R</sub> (\u2124<sub>q</sub>)<sup>\u00D7</sup>, s \u2261<sub>p</sub> g<sup>r</sup>,
 *        e \u2261<sub>q</sub> H(M \u2016 s), y \u2261<sub>q</sub> r + ex
 *      </td>
 *    </tr>
 *    <tr>
 *      <td style="font-weight: bold">Signature</td>
 *      <td style="padding-left: 20px">(e,y) \u2208 \u2124<sub>q</sub> \u00D7 \u2124<sub>q</sub></td>
 *    </tr>
 *    <tr>
 *      <td style="font-weight: bold">Verifying</td>
 *      <td style="padding-left: 20px">
 *        s \u2261<sub>p</sub> g<sup>y</sup>h<sup>-e</sup>,
 *        check if H(M \u2016 s) \u2261<sub>q</sub> e holds.
 *      </td>
 *    </tr>
 *    <tr>
 *      <td style="font-weight: bold">Correctness</td>
 *      <td style="padding-left: 20px">
 *        g<sup>y</sup>h<sup>-e</sup> \u2261<sub>p</sub> g<sup>y</sup>g<sup>-ex</sup> \u2261<sub>p</sub> g<sup>y-ex</sup> \u2261<sub>p</sub> g<sup>r</sup>
 *      </td>
 *    </tr>
 *  </tbody>
 * </table>
 * @author Christof Reichardt
 */
public class SchnorrSignature extends SignatureSpi implements Traceable {

  final private MessageDigest messageDigest;
  private SecureRandom secureRandom = new SecureRandom();
  private SchnorrPrivateKey schnorrPrivateKey;
  private SchnorrPublicKey schnorrPublicKey;
  private boolean initialisedForSigning;
  private boolean initialisedForVerification;
  private SchnorrSigParameterSpec schnorrSigParameterSpec = new SchnorrSigParameterSpec();
  private NonceGenerator nonceGenerator;

  /**
   * Creates a SchnorrSignature instance.
   * 
   * @throws NoSuchAlgorithmException if no suitable message digest algorithm has been found.
   */
  public SchnorrSignature() throws NoSuchAlgorithmException {
    this.messageDigest = digestInstance();
    this.initialisedForSigning = false;
    this.initialisedForVerification = false;
  }
  
  private MessageDigest digestInstance() throws NoSuchAlgorithmException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("MessageDigest", this, "digestInstance()");
    
    try {
      Provider provider = Security.getProvider(de.christofreichardt.crypto.Provider.NAME);
      String algorithmName;
      if (provider != null)
        algorithmName = provider.getProperty("de.christofreichardt.crypto.schnorrsignature.messageDigest", "SHA-256");
      else
        algorithmName = "SHA-256";
      
      tracer.out().printfIndentln("algorithmName = %s", algorithmName);
      
      return MessageDigest.getInstance(algorithmName);
    }
    finally {
      tracer.wayout();
    }
  }
  
  /**
   * Initialises the {@link SchnorrSignature SchnorrSignature} with the given arguments for a verification run.
   * 
   * @param publicKey specifies the PublicKey instance.
   * @throws InvalidKeyException if publicKey isn't a SchnorrPublicKey instance.
   */
  @Override
  protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "engineInitVerify(PublicKey publicKey)");
    
    try {
      tracer.out().printfIndentln("publicKey = %s", publicKey);
      
      if (!(publicKey instanceof SchnorrPublicKey))
        throw new InvalidKeyException("Need a SchnorrPublicKey instance.");
      
      this.schnorrPublicKey = (SchnorrPublicKey) publicKey;
      resetForVerifying();
    }
    finally {
      tracer.wayout();
    }
  }
  
  private void resetForVerifying() {
    this.messageDigest.reset();
    this.initialisedForVerification = true;
    this.initialisedForSigning = false;
  }

  /**
   * Initialises the {@link SchnorrSignature SchnorrSignature} with the given arguments for a signing run.
   * 
   * @param privateKey specifies the PrivateKey instance.
   * @throws InvalidKeyException if privateKey isn't a SchnorrPrivateKey instance.
   */
  @Override
  protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "engineInitSign(PrivateKey privateKey)");
    
    try {
      tracer.out().printfIndentln("privateKey = %s", privateKey);
      
      if (!(privateKey instanceof SchnorrPrivateKey))
        throw new InvalidKeyException("Need a SchnorrPrivateKey instance.");
      if (this.schnorrSigParameterSpec.getNonceGeneratorStrategy() == NonceGeneratorStrategy.PRIVATEKEY_MSG_HASH  &&  
          !(privateKey instanceof ExtSchnorrPrivateKey))
        throw new InvalidKeyException("Need a ExtSchnorrPrivateKey instance.");
      
      this.schnorrPrivateKey = (SchnorrPrivateKey) privateKey;
      resetForSigning();
    }
    finally {
      tracer.wayout();
    }
  }
  
  private void resetForSigning() {
    this.messageDigest.reset();
    switch (this.schnorrSigParameterSpec.getNonceGeneratorStrategy()) {
    case SECURE_RANDOM:
      this.nonceGenerator = new RandomNonceGenerator(this.schnorrPrivateKey.getSchnorrParams().getQ(), this.secureRandom);
      break;
    case PRIVATEKEY_MSG_HASH:
      this.nonceGenerator = new DeterministicNonceGenerator(this.schnorrPrivateKey.getSchnorrParams().getQ(), ((ExtSchnorrPrivateKey) this.schnorrPrivateKey).getExtKeyBytes());
      break;
    default:
      this.nonceGenerator = new RandomNonceGenerator(this.schnorrPrivateKey.getSchnorrParams().getQ(), this.secureRandom);
      break;
    }
    
    this.initialisedForSigning = true;
    this.initialisedForVerification = false;
  }

  /**
   * Initialises the {@link SchnorrSignature SchnorrSignature} with the given arguments for a verification run.
   * 
   * @param privateKey specifies the PrivateKey instance.
   * @param secureRandom specifies a source of randomness.
   * @throws InvalidKeyException if privateKey isn't a SchnorrPrivateKey instance
   */
  @Override
  protected void engineInitSign(PrivateKey privateKey, SecureRandom secureRandom) throws InvalidKeyException {
    this.secureRandom = secureRandom;
    engineInitSign(privateKey);
  }

  /**
   * Updates the {@link SchnorrSignature SchnorrSignature} with the given input byte.
   * 
   * @param input the input byte.
   * @throws java.security.SignatureException if the {@link SchnorrSignature SchnorrSignature} hasn't been properly initialized.
   */
  @Override
  protected void engineUpdate(byte input) throws SignatureException {
    if (!this.initialisedForSigning && !this.initialisedForVerification)
      throw new SignatureException("Signature scheme hasn't been initialized.");
    
    this.messageDigest.update(input);
    this.nonceGenerator.update(input);
  }

  /**
   * Updates the {@link SchnorrSignature SchnorrSignature} with the given input bytes beginning at the position specified by offset
   * up to length bytes.
   * 
   * @param bytes the input bytes.
   * @param offset the offset
   * @param length the number of the significant bytes
   * @throws java.security.SignatureException if the {@link SchnorrSignature SchnorrSignature} hasn't been properly initialized.
   */
  @Override
  protected void engineUpdate(byte[] bytes, int offset, int length) throws SignatureException {
    if (!this.initialisedForSigning && !this.initialisedForVerification)
      throw new SignatureException("Signature scheme hasn't been initialized.");
    
    this.messageDigest.update(bytes, offset, length);
    this.nonceGenerator.update(bytes, offset, length);
  }

  /**
   * First the method updates the message digest by appending s \u2261<sub>p</sub> g<sup>r</sup>,
   * second it computes (e,y) \u2208 \u2124<sub>q</sub> \u00D7 \u2124<sub>q</sub> with e \u2261<sub>q</sub> H(M \u2016 s) and
   * y \u2261<sub>q</sub> r + ex.
   * 
   * @return the byte representation of (e \u2016 y)
   * @throws java.security.SignatureException if the {@link SchnorrSignature SchnorrSignature} hasn't been properly initialized.
   */
  @Override
  protected byte[] engineSign() throws SignatureException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("byte[]", this, "engineSign()");
    
    try {
      try {
        if (!this.initialisedForSigning)
          throw new SignatureException("Signature scheme hasn't been initialized for signing.");
        
        final BigInteger q = this.schnorrPrivateKey.getSchnorrParams().getQ();
        final BigInteger x = this.schnorrPrivateKey.getX();
        final int Q_BYTES = q.bitLength()/8 + 1;
        
        tracer.out().printfIndentln("Q_BYTES = %d", Q_BYTES);
        
        BigInteger e, r, y;
        byte[] digestBytes;
        do {
          do {
            r = this.nonceGenerator.nonce();
          } while (r.equals(BigInteger.ZERO));

          digestBytes = concatForSigning(r);
          digestBytes = expandMessageDigest(digestBytes);
          e = new BigInteger(digestBytes).mod(q);
          y = r.subtract(e.multiply(x)).mod(q);
        } while (e.equals(BigInteger.ZERO) || y.equals(BigInteger.ZERO));
        byte[] eBytes = e.toByteArray();
        byte[] yBytes = y.toByteArray();
        
        tracer.out().printfIndentln("BigInteger(digestBytes) = %s", new BigInteger(digestBytes));
        tracer.out().printfIndentln("e(%d) = %d", e.bitLength(), e);
        tracer.out().printfIndentln("--- eBytes(%d) ---", eBytes.length);
        traceBytes(eBytes);
        tracer.out().printfIndentln("y(%d) = %d", y.bitLength(), y);
        tracer.out().printfIndentln("--- yBytes(%d) ---", yBytes.length);
        traceBytes(yBytes);
        
        byte[] signatureBytes = new byte[2*Q_BYTES];
        Arrays.fill(signatureBytes, (byte) 0);
        System.arraycopy(eBytes, 0, signatureBytes, Q_BYTES - eBytes.length, eBytes.length);
        System.arraycopy(yBytes, 0, signatureBytes, Q_BYTES + Q_BYTES - yBytes.length, yBytes.length);
        
        return signatureBytes;
      }
      finally {
        resetForSigning();
      }
    }
    finally {
      tracer.wayout();
    }
  }
  
  private byte[] expandMessageDigest(byte[] digestBytes) {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("byte[]", this, "expandMessageDigest(byte[] digestBytes)");
    
    try {
      tracer.out().printfIndentln("--- digestBytes(%d) ---", digestBytes.length);
      traceBytes(digestBytes);
      
      final BigInteger q = this.schnorrPrivateKey.getSchnorrParams().getQ();
      final int UNIFORM_DISTRIBUTION_SURCHARGE = 16;
      byte[] expandedDigestBytes;
      if (digestBytes.length*8 < q.bitLength() + UNIFORM_DISTRIBUTION_SURCHARGE) {
        int expandedByteLength = (q.bitLength() + UNIFORM_DISTRIBUTION_SURCHARGE)/8;
        
        tracer.out().printfIndentln("expandedByteLength = %d", expandedByteLength);
        
        expandedDigestBytes = Arrays.copyOf(digestBytes, expandedByteLength);
        byte[] additionalBytes = new byte[expandedByteLength - digestBytes.length];
        SecureRandom expander;
        try {
          expander = SecureRandom.getInstance("SHA1PRNG");
        }
        catch (NoSuchAlgorithmException ex) {
          throw new RuntimeException(ex);
        }
        expander.setSeed(digestBytes);
        expander.nextBytes(additionalBytes);
        System.arraycopy(additionalBytes, 0, expandedDigestBytes, digestBytes.length, additionalBytes.length);
        
        tracer.out().printfIndentln("--- expandedDigestBytes(%d) ---", expandedDigestBytes.length);
        traceBytes(expandedDigestBytes);
      }
      else
        expandedDigestBytes = digestBytes;
      
      return expandedDigestBytes;
    }
    finally {
      tracer.wayout();
    }
  }
  
  private byte[] concatForSigning(BigInteger r) throws SignatureException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("byte[]", this, "concatForSigning(BigInteger r)");
    
    try {
      final BigInteger p = this.schnorrPrivateKey.getSchnorrParams().getP();
      final BigInteger g = this.schnorrPrivateKey.getSchnorrParams().getG();
      
      BigInteger s;
      s = g.modPow(r, p);
      
      tracer.out().printfIndentln("s(%d) = %d", s.bitLength(), s);
      
      try {
        MessageDigest messageDigest = (MessageDigest) this.messageDigest.clone();
        messageDigest.update(s.toByteArray());
        
        return messageDigest.digest();
      }
      catch (CloneNotSupportedException ex) {
        tracer.logException(LogLevel.ERROR, ex, getClass(), "byte[] concatForSigning(BigInteger r)");
        throw new SignatureException(ex);
      }
    }
    finally {
      tracer.wayout();
    }
  }

  /**
   * Recycles (e,y) from the signatureBytes, computes s \u2261<sub>p</sub> g<sup>y</sup>h<sup>-e</sup> and appends the byte representation of
   * s to the message digest. Thereupon it checks if H(M \u2016 s) \u2261<sub>q</sub> e holds.
   * 
   * @param signatureBytes the byte representation of (e,y).
   * @return indicates if the verification has been successfull.
   * @throws java.security.SignatureException if the {@link SchnorrSignature SchnorrSignature} hasn't been properly initialized.
   */
  @Override
  protected boolean engineVerify(byte[] signatureBytes) throws SignatureException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("boolean", this, "engineVerify(byte[] signatureBytes)");
    
    try {
      try {
        if (!this.initialisedForVerification)
          throw new SignatureException("Signature scheme hasn't been initialized for verification.");
        
        final BigInteger q = this.schnorrPublicKey.getSchnorrParams().getQ();
        BigInteger e = concatForVerifying(signatureBytes);
        byte[] digestBytes = this.messageDigest.digest();
        digestBytes = expandMessageDigest(digestBytes);
        
        return new BigInteger(digestBytes).mod(q).equals(e);
      }
      finally {
        resetForVerifying();
      }
    }
    finally {
      tracer.wayout();
    }
  }
  
  private BigInteger concatForVerifying(byte[] signatureBytes) {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("BigInteger", this, "concatForVerifying(byte[] signatureBytes)");
    
    try {
      final BigInteger p = this.schnorrPublicKey.getSchnorrParams().getP();
      final BigInteger g = this.schnorrPublicKey.getSchnorrParams().getG();
      final BigInteger q = this.schnorrPublicKey.getSchnorrParams().getQ();
      final BigInteger h = this.schnorrPublicKey.getH();
      final int Q_BYTES = q.bitLength()/8 + 1;
      
      byte[] eBytes = Arrays.copyOfRange(signatureBytes, 0, Q_BYTES);
      byte[] yBytes = Arrays.copyOfRange(signatureBytes, Q_BYTES, signatureBytes.length);
      
      tracer.out().printfIndentln("--- eBytes(%d) ---", eBytes.length);
      traceBytes(eBytes);
      tracer.out().printfIndentln("--- yBytes(%d) ---", yBytes.length);
      traceBytes(yBytes);
      
      BigInteger e = new BigInteger(eBytes);
      BigInteger y = new BigInteger(yBytes);
      
      tracer.out().printfIndentln("e(%d) = %d", e.bitLength(), e);
      tracer.out().printfIndentln("y(%d) = %d", y.bitLength(), y);

      BigInteger s = g.modPow(y, p).multiply(h.modPow(e, p)).mod(p);
      
      tracer.out().printfIndentln("s(%d) = %d", s.bitLength(), s);
      
      this.messageDigest.update(s.toByteArray());
      
      return e;
    }
    finally {
      tracer.wayout();
    }
  }
  
  @Override
  @SuppressWarnings("deprecation")
  protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
    throw new UnsupportedOperationException("Unsupported operation.");
  }

  @Override
  @SuppressWarnings("deprecation")
  protected Object engineGetParameter(String param) throws InvalidParameterException {
    throw new UnsupportedOperationException("Unsupported operation..");
  }

  @Override
  protected AlgorithmParameters engineGetParameters() {
    throw new UnsupportedOperationException("Unsupported operation.");
  }

  @Override
  protected void engineSetParameter(AlgorithmParameterSpec algorithmParameterSpec) throws InvalidAlgorithmParameterException {
    if (!(algorithmParameterSpec instanceof SchnorrSigParameterSpec))
      throw new InvalidAlgorithmParameterException("Need a 'SchnorrSigParameterSpec'.");
    
    this.schnorrSigParameterSpec = (SchnorrSigParameterSpec) algorithmParameterSpec;
  }
  
  protected void traceBytes(byte[] bytes) {
    AbstractTracer tracer = getCurrentTracer();
    for (int i=0; i<bytes.length; i++) {
      if (i % 16 == 0) {
        if (i != 0)
          tracer.out().println();
        tracer.out().printIndentString();
      }
      tracer.out().printf("%3d ", bytes[i] & 255);
    }
    tracer.out().println();
  }

  @Override
  public AbstractTracer getCurrentTracer() {
    return TracerFactory.getInstance().getCurrentPoolTracer();
  }

}
