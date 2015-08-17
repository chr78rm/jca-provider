package de.christofreichardt.crypto;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.SignatureException;

public interface NonceGenerator {
  void update(byte input);
  void update(byte[] bytes, int offset, int length);
  BigInteger nonce() throws SignatureException;
  void copy(MessageDigest messageDigest) throws SignatureException;
  void reset(SecureRandom secureRandom, BigInteger modul, byte[] extKeyBytes);
}
