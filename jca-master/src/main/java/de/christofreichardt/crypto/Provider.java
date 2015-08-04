package de.christofreichardt.crypto;

/**
 * The master class of a provider for the Java Cryptography Architecture (JCA). It maps algorithm names
 * on fully qualified class names.
 * 
 * @author Christof Reichardt
 */
public class Provider extends java.security.Provider {
  private static final long serialVersionUID = 1L;
  static public final String NAME = "CryptoChr";

  public Provider() {
    super(NAME,
        0.1,
        NAME + " v0.1.0 JCA provider implementing the Schnorr Signatur on Schnorr groups and "
        + "their equivalents on Elliptic Curves as well as the RabinSAEP crypto system.");
    init();
  }

  private void init() {
    put("KeyPairGenerator.SchnorrSignature", "de.christofreichardt.crypto.schnorrsignature.KeyPairGenerator");
    put("Signature.SchnorrSignature", "de.christofreichardt.crypto.schnorrsignature.SchnorrSignature");
    put("KeyPairGenerator.ECSchnorrSignature", "de.christofreichardt.crypto.ecschnorrsignature.KeyPairGenerator");
    put("Signature.ECSchnorrSignatureWithSHA256", "de.christofreichardt.crypto.ecschnorrsignature.SignatureWithSHA256");
    
    // configuration
    put("de.christofreichardt.scala.ellipticcurve.affine.multiplicationMethod", "MontgomeryLadder2");
    put("de.christofreichardt.crypto.schnorrsignature.messageDigest", "SHA-512");
  }
}
