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
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
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
public class SignatureWithSHA256 extends SignatureSpi implements Traceable {

  /**
   * the length of the used message digest in bytes
   */
  static final public int DIGEST_LENGTH = 32;
  
  final private MessageDigest messageDigest;
  private SecureRandom secureRandom = new SecureRandom();
  private SchnorrPrivateKey schnorrPrivateKey;
  private BigInteger r;
  private SchnorrPublicKey schnorrPublicKey;
  private boolean initialisedForSigning;
  private boolean initialisedForVerification;

  /**
   * Creates a SHA-256 message digest algorithm instance.
   * @throws NoSuchAlgorithmException if no SHA-256 message digest algorithm has been found.
   */
  public SignatureWithSHA256() throws NoSuchAlgorithmException {
    this.messageDigest = MessageDigest.getInstance("SHA-256");
    this.initialisedForSigning = false;
    this.initialisedForVerification = false;
  }
  
  /**
   * Initialises the {@link SignatureWithSHA256 SignatureWithSHA256} with the given arguments for a verification run.
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
      this.messageDigest.reset();
      this.initialisedForVerification = true;
      this.initialisedForSigning = false;
    }
    finally {
      tracer.wayout();
    }
  }

  /**
   * Initialises the {@link SignatureWithSHA256 SignatureWithSHA256} with the given arguments for a signing run.
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
      
      this.schnorrPrivateKey = (SchnorrPrivateKey) privateKey;
      this.messageDigest.reset();
      
      final BigInteger q = this.schnorrPrivateKey.getSchnorrParams().getQ();
      do {
        this.r = new BigInteger(q.bitLength()*2, this.secureRandom).mod(q);
      } while (this.r.equals(BigInteger.ZERO));
      
      this.initialisedForSigning = true;
      this.initialisedForVerification = false;
    }
    finally {
      tracer.wayout();
    }
  }

  /**
   * Initialises the {@link SignatureWithSHA256 SignatureWithSHA256} with the given arguments for a verification run.
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
   * Updates the {@link SignatureWithSHA256 SignatureWithSHA256} with the given input byte.
   * 
   * @param input the input byte.
   * @throws java.security.SignatureException if the {@link SignatureWithSHA256 SignatureWithSHA256} hasn't been properly initialized.
   */
  @Override
  protected void engineUpdate(byte input) throws SignatureException {
    if (!this.initialisedForSigning && !this.initialisedForVerification)
      throw new SignatureException("Signature scheme hasn't been initialized.");
    
    this.messageDigest.update(input);
  }

  /**
   * Updates the {@link SignatureWithSHA256 SignatureWithSHA256} with the given input bytes beginning at the position specified by offset
   * up to length bytes.
   * 
   * @param bytes the input bytes.
   * @param offset the offset
   * @param length the number of the significant bytes
   * @throws java.security.SignatureException if the {@link SignatureWithSHA256 SignatureWithSHA256} hasn't been properly initialized.
   */
  @Override
  protected void engineUpdate(byte[] bytes, int offset, int length) throws SignatureException {
    if (!this.initialisedForSigning && !this.initialisedForVerification)
      throw new SignatureException("Signature scheme hasn't been initialized.");
    
    this.messageDigest.update(bytes, offset, length);
  }

  /**
   * First the method updates the message digest by appending s \u2261<sub>p</sub> g<sup>r</sup>,
   * second it computes (e,y) \u2208 \u2124<sub>q</sub> \u00D7 \u2124<sub>q</sub> with e \u2261<sub>q</sub> H(M \u2016 s) and
   * y \u2261<sub>q</sub> r + ex.
   * 
   * @return the byte representation of (e \u2016 y)
   * @throws java.security.SignatureException if the {@link SignatureWithSHA256 SignatureWithSHA256} hasn't been properly initialized.
   */
  @Override
  protected byte[] engineSign() throws SignatureException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("byte[]", this, "engineSign()");
    
    try {
      if (!this.initialisedForSigning)
        throw new SignatureException("Signature scheme hasn't been initialized for signing.");
      
      concatForSigning();
      byte[] digestBytes = this.messageDigest.digest();
      
      assert digestBytes.length == DIGEST_LENGTH;
      
      final BigInteger q = this.schnorrPrivateKey.getSchnorrParams().getQ();
      final BigInteger x = this.schnorrPrivateKey.getX();
      
      BigInteger e = new BigInteger(digestBytes).mod(q);
      BigInteger y = e.multiply(x).add(this.r).mod(q);
      byte[] yBytes = y.toByteArray();
      
      tracer.out().printfIndentln("e(%d) = %d", e.bitLength(), e);
      tracer.out().printfIndentln("y(%d) = %d", y.bitLength(), y);
      tracer.out().printfIndentln("yBytes.length = %d", yBytes.length);
      
      byte[] signatureBytes = Arrays.copyOf(digestBytes, DIGEST_LENGTH + yBytes.length);
      System.arraycopy(yBytes, 0, signatureBytes, DIGEST_LENGTH, yBytes.length);
      
      return signatureBytes;
    }
    finally {
      tracer.wayout();
    }
  }
  
  private void concatForSigning() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "concatForSigning()");
    
    try {
      final BigInteger p = this.schnorrPrivateKey.getSchnorrParams().getP();
      final BigInteger q = this.schnorrPrivateKey.getSchnorrParams().getQ();
      final BigInteger g = this.schnorrPrivateKey.getSchnorrParams().getG();
      
      BigInteger s;
      s = g.modPow(this.r, p);
      
      tracer.out().printfIndentln("s(%d) = %d", s.bitLength(), s);
      
      this.messageDigest.update(s.toByteArray());
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
   * @throws java.security.SignatureException if the {@link SignatureWithSHA256 SignatureWithSHA256} hasn't been properly initialized.
   */
  @Override
  protected boolean engineVerify(byte[] signatureBytes) throws SignatureException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("boolean", this, "engineVerify(byte[] signatureBytes)");
    
    try {
      if (!this.initialisedForVerification)
        throw new SignatureException("Signature scheme hasn't been initialized for verification.");
      
      tracer.out().printIndentString();
      tracer.out().printf("signatureBytes(%d) = ", signatureBytes.length);
      traceBytes(signatureBytes);
      tracer.out().println();
      
      final BigInteger q = this.schnorrPublicKey.getSchnorrParams().getQ();
      
      BigInteger e = concatForVerifying(signatureBytes);
      byte[] digestBytes = this.messageDigest.digest();
      
      return new BigInteger(digestBytes).mod(q).equals(e);
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
      
      byte[] eBytes = Arrays.copyOfRange(signatureBytes, 0, DIGEST_LENGTH);
      BigInteger e = new BigInteger(eBytes).mod(q);
      byte[] yBytes = Arrays.copyOfRange(signatureBytes, DIGEST_LENGTH, signatureBytes.length);
      BigInteger y = new BigInteger(yBytes);
      BigInteger s = g.modPow(y, p).multiply(h.modPow(e.negate(), p)).mod(p);
      
      tracer.out().printfIndentln("e(%d) = %d", e.bitLength(), e);
      tracer.out().printfIndentln("y(%d) = %d", y.bitLength(), y);
      tracer.out().printfIndentln("s(%d) = %d", s.bitLength(), s);
      
      this.messageDigest.update(s.toByteArray());
      
      return e;
    }
    finally {
      tracer.wayout();
    }
  }
  
  private void traceBytes(byte[] bytes) {
    AbstractTracer tracer = getCurrentTracer();
    for (byte signatureByte : bytes) {
      tracer.out().print(signatureByte & 255);
      tracer.out().print(' ');
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
  protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
    throw new UnsupportedOperationException("Unsupported operation.");
  }
  
  

  @Override
  public AbstractTracer getCurrentTracer() {
    return TracerFactory.getInstance().getCurrentPoolTracer();
  }

}
