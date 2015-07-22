package de.christofreichardt.crypto.schnorrsignature;

import java.math.BigInteger;

public interface NonceGenerator {
  void update(byte input);
  void update(byte[] bytes, int offset, int length);
  BigInteger nonce();
}
