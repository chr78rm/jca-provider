package de.christofreichardt.crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.SignatureException;

/**
 * A generator for unpredictable nonces used by the signature process. The generated nonces might be completely 
 * random or fully deterministic. Note that while the nonces might be fully deterministic they are nervertheless
 * unpredictable for outsiders without knowledge of certain portions of the private key.
 * 
 * @author Christof Reichardt
 */
public interface NonceGenerator {
  /**
   * Might update an internal message digest (optional operation).
   * 
   * @param input the byte to use for the update
   */
  void update(byte input);
  
  /**
   * Might update an internal message digest (optional operation).
   * 
   * @param bytes the array of bytes.
   * @param offset the offset to start from in the array of bytes.
   * @param length the number of bytes to use, starting at offset.
   */
  void update(byte[] bytes, int offset, int length);
  
  /**
   * Generates the actual nonce based upon the acquired internal state or rather simply by relying on 
   * a SecureRandom instance.
   * 
   * @return the generated nonce.
   * @throws SignatureException indicates a problem when generating the nonce.
   */
  BigInteger nonce() throws SignatureException;
  
  /**
   * Clones the given MessageDigest.
   * 
   * @param messageDigest the to be cloned MessageDigest.
   * @throws SignatureException indicates a problem during the cloning, e.g. the MessageDigest might not be cloneable.
   */
  void copy(MessageDigest messageDigest) throws SignatureException;
  
  /**
   * Resets the NonceGenerator by using the given parameter. 
   * 
   * @param secureRandom a SecureRandom instance (can be null if not needed by the particular NonceGenrator).
   * @param modul used to map the nonce onto \u2124<sub>q</sub>.
   * @param extKeyBytes might be used as entropy input foe deterministic nonces (can be null if not needed by the particular NonceGenrator).
   */
  void reset(SecureRandom secureRandom, BigInteger modul, byte[] extKeyBytes);
}
