package de.christofreichardt.crypto.examples;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import de.christofreichardt.crypto.HmacSHA256PRNGNonceGenerator;
import de.christofreichardt.crypto.NonceGenerator;
import de.christofreichardt.crypto.UniformRandomNonceGenerator;
import de.christofreichardt.crypto.schnorrsignature.SchnorrPublicKey;
import de.christofreichardt.crypto.schnorrsignature.SchnorrSigKeyGenParameterSpec;
import de.christofreichardt.crypto.schnorrsignature.SchnorrSigKeyGenParameterSpec.Strength;
import de.christofreichardt.crypto.schnorrsignature.SchnorrSigParameterSpec;

public class Main {
  static public final Logger LOGGER = Logger.getLogger(Main.class.getName());
  private final Properties properties;
  
  public Main() throws IOException {
    this.properties = readProperties();
  }
  
  private Properties readProperties() throws IOException {
    File file = new File("examples.properties");
    Properties properties = new Properties();
    try (FileInputStream fileInputStream = new FileInputStream(file)) {
      properties.load(fileInputStream);
    }
    
    return properties;
  }
  
  private void example1() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    LOGGER.log(Level.INFO, "-> Example1: Key pairs with default strength.");
    LOGGER.log(Level.INFO, "Reading message bytes ...");
    File file = new File("../data/loremipsum.txt");
    byte[] bytes = Files.readAllBytes(file.toPath());
    
    LOGGER.log(Level.INFO, "Generating key pair ...");
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SchnorrSignature");
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    SchnorrPublicKey publicKey = (SchnorrPublicKey) keyPair.getPublic();
    LOGGER.log(Level.INFO, "bitlength(q) = {0}", new Object[]{publicKey.getSchnorrParams().getQ().bitLength()});
    LOGGER.log(Level.INFO, "bitlength(p) = {0}", new Object[]{publicKey.getSchnorrParams().getP().bitLength()});
    
    assert publicKey.getSchnorrParams().getQ().bitLength() == 512;
    assert publicKey.getSchnorrParams().getP().bitLength() == 2048;
    
    LOGGER.log(Level.INFO, "Signing ...");
    Signature signature = Signature.getInstance("SchnorrSignature");
    signature.initSign(keyPair.getPrivate());
    signature.update(bytes);
    byte[] signatureBytes = signature.sign();
    
    LOGGER.log(Level.INFO, "Verifying ...");
    signature.initVerify(keyPair.getPublic());
    signature.update(bytes);
    boolean verified = signature.verify(signatureBytes);
    
    assert verified;
  }
  
  private void example2() throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {
    LOGGER.log(Level.INFO, "-> Example2: Key pairs with minimal strength.");
    LOGGER.log(Level.INFO, "Reading message bytes ...");
    File file = new File("../data/loremipsum.txt");
    byte[] bytes = Files.readAllBytes(file.toPath());
    
    LOGGER.log(Level.INFO, "Generating key pair ...");
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SchnorrSignature");
    SchnorrSigKeyGenParameterSpec schnorrSigGenParameterSpec = new SchnorrSigKeyGenParameterSpec(Strength.MINIMAL);
    keyPairGenerator.initialize(schnorrSigGenParameterSpec);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    SchnorrPublicKey publicKey = (SchnorrPublicKey) keyPair.getPublic();
    LOGGER.log(Level.INFO, "bitlength(q) = {0}", new Object[]{publicKey.getSchnorrParams().getQ().bitLength()});
    LOGGER.log(Level.INFO, "bitlength(p) = {0}", new Object[]{publicKey.getSchnorrParams().getP().bitLength()});
    
    assert publicKey.getSchnorrParams().getQ().bitLength() == 160;
    assert publicKey.getSchnorrParams().getP().bitLength() == 1024;
    
    LOGGER.log(Level.INFO, "Signing ...");
    Signature signature = Signature.getInstance("SchnorrSignature");
    signature.initSign(keyPair.getPrivate());
    signature.update(bytes);
    byte[] signatureBytes = signature.sign();
    
    LOGGER.log(Level.INFO, "Verifying ...");
    signature.initVerify(keyPair.getPublic());
    signature.update(bytes);
    boolean verified = signature.verify(signatureBytes);
    
    assert verified;
  }
  
  private void example3() throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException  {
    LOGGER.log(Level.INFO, "-> Example3: Key pairs with strong strength.");
    LOGGER.log(Level.INFO, "Reading message bytes ...");
    File file = new File("../data/loremipsum.txt");
    byte[] bytes = Files.readAllBytes(file.toPath());
    
    LOGGER.log(Level.INFO, "Generating key pair ...");
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SchnorrSignature");
    SchnorrSigKeyGenParameterSpec schnorrSigGenParameterSpec = new SchnorrSigKeyGenParameterSpec(Strength.STRONG);
    keyPairGenerator.initialize(schnorrSigGenParameterSpec);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    SchnorrPublicKey publicKey = (SchnorrPublicKey) keyPair.getPublic();
    LOGGER.log(Level.INFO, "bitlength(q) = {0}", new Object[]{publicKey.getSchnorrParams().getQ().bitLength()});
    LOGGER.log(Level.INFO, "bitlength(p) = {0}", new Object[]{publicKey.getSchnorrParams().getP().bitLength()});
    
    assert publicKey.getSchnorrParams().getQ().bitLength() == 1024;
    assert publicKey.getSchnorrParams().getP().bitLength() == 4096;
    
    LOGGER.log(Level.INFO, "Signing ...");
    Signature signature = Signature.getInstance("SchnorrSignature");
    signature.initSign(keyPair.getPrivate());
    signature.update(bytes);
    byte[] signatureBytes = signature.sign();
    
    LOGGER.log(Level.INFO, "Verifying ...");
    signature.initVerify(keyPair.getPublic());
    signature.update(bytes);
    boolean verified = signature.verify(signatureBytes);
    
    assert verified;
  }
  
  private void example4() throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    LOGGER.log(Level.INFO, "-> Example4: Key pairs with custom strength.");
    
    LOGGER.log(Level.INFO, "Reading message bytes ...");
    File file = new File("../data/loremipsum.txt");
    byte[] bytes = Files.readAllBytes(file.toPath());
    
    LOGGER.log(Level.INFO, "Generating key pair ...");
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SchnorrSignature");
    final int T = 256;
    final int L = 1024;
    SchnorrSigKeyGenParameterSpec schnorrSigGenParameterSpec = new SchnorrSigKeyGenParameterSpec(L, T, false);
    keyPairGenerator.initialize(schnorrSigGenParameterSpec);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    SchnorrPublicKey publicKey = (SchnorrPublicKey) keyPair.getPublic();
    LOGGER.log(Level.INFO, "bitlength(q) = {0}", new Object[]{publicKey.getSchnorrParams().getQ().bitLength()});
    LOGGER.log(Level.INFO, "bitlength(p) = {0}", new Object[]{publicKey.getSchnorrParams().getP().bitLength()});
    
    assert publicKey.getSchnorrParams().getQ().bitLength() == 256;
    
    LOGGER.log(Level.INFO, "Signing ...");
    Signature signature = Signature.getInstance("SchnorrSignature");
    signature.initSign(keyPair.getPrivate());
    signature.update(bytes);
    byte[] signatureBytes = signature.sign();
    
    LOGGER.log(Level.INFO, "Verifying ...");
    signature.initVerify(keyPair.getPublic());
    signature.update(bytes);
    boolean verified = signature.verify(signatureBytes);
    
    assert verified;
  }
  
  private void example5() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    LOGGER.log(Level.INFO, "-> Example5: Custom SecureRandom.");
    
    LOGGER.log(Level.INFO, "Generating key pair ...");
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SchnorrSignature");
    KeyPair keyPair = keyPairGenerator.generateKeyPair();

    LOGGER.log(Level.INFO, "Reading message bytes ...");
    File file = new File("../data/loremipsum.txt");
    byte[] bytes = Files.readAllBytes(file.toPath());
    
    LOGGER.log(Level.INFO, "Retrieving SHA1PRNG ...");
    SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");

    LOGGER.log(Level.INFO, "Signing ...");
    Signature signature = Signature.getInstance("SchnorrSignature");
    signature.initSign(keyPair.getPrivate(), secureRandom);
    signature.update(bytes);
    byte[] signatureBytes = signature.sign();
    
    LOGGER.log(Level.INFO, "Verifying ...");
    signature.initVerify(keyPair.getPublic());
    signature.update(bytes);
    boolean verified = signature.verify(signatureBytes);
    
    assert verified;
  }
  
  private void example6() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    LOGGER.log(Level.INFO, "-> Example6: NIO.");
    
    LOGGER.log(Level.INFO, "Generating key pair ...");
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SchnorrSignature");
    KeyPair keyPair = keyPairGenerator.generateKeyPair();

    LOGGER.log(Level.INFO, "Checking specified file ...");
    assert this.properties.containsKey("de.christofreichardt.crypto.examples.largeFile");
    File file = new File(this.properties.getProperty("de.christofreichardt.crypto.examples.largeFile"));
    assert file.exists();
    
    LOGGER.log(Level.INFO, "Processing {0} ...", file.getPath());
    Signature signature = Signature.getInstance("SchnorrSignature");
    signature.initSign(keyPair.getPrivate());
    int bufferSize = 512;
    ByteBuffer buffer = ByteBuffer.allocate(bufferSize);
    byte[] bytes = new byte[bufferSize];
    try (FileInputStream fileInputStream = new FileInputStream(file)) {
      FileChannel fileChannel = fileInputStream.getChannel();
      do {
        int read = fileChannel.read(buffer);
        if (read == -1)
          break;
        buffer.flip();
        buffer.get(bytes, 0, read);
        signature.update(bytes, 0, read);
        buffer.clear();
      } while(true);
    }
    
    LOGGER.log(Level.INFO, "Signing ...");
    byte[] signatureBytes = signature.sign();
    
    LOGGER.log(Level.INFO, "Processing {0} ...", file.getPath());
    signature.initVerify(keyPair.getPublic());
    try (FileInputStream fileInputStream = new FileInputStream(file)) {
      FileChannel fileChannel = fileInputStream.getChannel();
      do {
        int read = fileChannel.read(buffer);
        if (read == -1)
          break;
        buffer.flip();
        buffer.get(bytes, 0, read);
        signature.update(bytes, 0, read);
        buffer.clear();
      } while(true);
    }
    
    LOGGER.log(Level.INFO, "Verifying ...");
    boolean verified = signature.verify(signatureBytes);
    
    assert verified;
  }
  
  private void example7() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidAlgorithmParameterException {
    LOGGER.log(Level.INFO, "-> Example7: DeterministicNonceGenerator.");
    
    LOGGER.log(Level.INFO, "Generating key pair ...");
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SchnorrSignature");
    SchnorrSigKeyGenParameterSpec schnorrSigKeyGenParameterSpec = new SchnorrSigKeyGenParameterSpec(Strength.DEFAULT, true);
    keyPairGenerator.initialize(schnorrSigKeyGenParameterSpec);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();

    LOGGER.log(Level.INFO, "Reading message bytes ...");
    File file = new File("../data/loremipsum.txt");
    byte[] bytes = Files.readAllBytes(file.toPath());

    LOGGER.log(Level.INFO, "Signing ...");
    Signature signature = Signature.getInstance("SchnorrSignature");
    NonceGenerator nonceGenerator = new HmacSHA256PRNGNonceGenerator();
    SchnorrSigParameterSpec schnorrSigParameterSpec = new SchnorrSigParameterSpec(nonceGenerator);
    signature.setParameter(schnorrSigParameterSpec);
    signature.initSign(keyPair.getPrivate());
    signature.update(bytes);
    byte[] signatureBytes = signature.sign();
    
    LOGGER.log(Level.INFO, "Verifying ...");
    signature.initVerify(keyPair.getPublic());
    signature.update(bytes);
    boolean verified = signature.verify(signatureBytes);
    
    assert verified;
  }
  
  private void example8() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidAlgorithmParameterException {
    LOGGER.log(Level.INFO, "-> Example7: UniformRandomNonceGenerator.");
    
    LOGGER.log(Level.INFO, "Generating key pair ...");
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SchnorrSignature");
    KeyPair keyPair = keyPairGenerator.generateKeyPair();

    LOGGER.log(Level.INFO, "Reading message bytes ...");
    File file = new File("../data/loremipsum.txt");
    byte[] bytes = Files.readAllBytes(file.toPath());

    LOGGER.log(Level.INFO, "Signing ...");
    Signature signature = Signature.getInstance("SchnorrSignature");
    NonceGenerator nonceGenerator = new UniformRandomNonceGenerator();
    SchnorrSigParameterSpec schnorrSigParameterSpec = new SchnorrSigParameterSpec(nonceGenerator);
    signature.setParameter(schnorrSigParameterSpec);
    signature.initSign(keyPair.getPrivate());
    signature.update(bytes);
    byte[] signatureBytes = signature.sign();
    
    LOGGER.log(Level.INFO, "Verifying ...");
    signature.initVerify(keyPair.getPublic());
    signature.update(bytes);
    boolean verified = signature.verify(signatureBytes);
    
    assert verified;
  }

  public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidAlgorithmParameterException {
    LOGGER.info("Adding provider ...");
    Provider provider = new de.christofreichardt.crypto.Provider();
    Security.addProvider(provider);
    
    Main main = new Main();
    if (args.length == 0) {
      main.example1();
      main.example2();
      main.example3();
      main.example4();
      main.example5();
      main.example6();
      main.example7();
      main.example8();
    }
    else {
      int nr = Integer.parseInt(args[0]);
      switch (nr) {
      case 1:
        main.example1();
        break;
      case 2:
        main.example2();
        break;
      case 3:
        main.example3();
        break;
      case 4:
        main.example4();
        break;
      case 5:
        main.example5();
        break;
      case 6:
        main.example6();
        break;
      case 7:
        main.example7();
        break;
      case 8:
        main.example8();
        break;
      default:
        break;
      }
    }
  }

}
