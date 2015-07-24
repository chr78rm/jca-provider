package de.christofreichardt.crypto.schnorrsignature;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Properties;

import org.junit.Test;

import de.christofreichardt.crypto.schnorrsignature.SchnorrSigKeyGenParameterSpec.Strength;
import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;

public class ExamplesUnit implements Traceable {
  final protected Properties properties;
  
  public ExamplesUnit(Properties properties) {
    this.properties = properties;
  }

  @Test
  public void example1() throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "example1()");
    
    try {
      Provider provider = new de.christofreichardt.crypto.Provider();
      Security.addProvider(provider);
      try {
        File file = new File("../data/loremipsum.txt");
        byte[] bytes = Files.readAllBytes(file.toPath());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SchnorrSignature");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        Signature signature = Signature.getInstance("SchnorrSignatureWithSHA256");
        signature.initSign(keyPair.getPrivate());
        signature.update(bytes);
        byte[] signatureBytes = signature.sign();
        signature.initVerify(keyPair.getPublic());
        signature.update(bytes);
        boolean verified = signature.verify(signatureBytes);
        
        tracer.out().printfIndentln("verified = %b", verified);
        
        assert verified;
      }
      finally {
        Security.removeProvider(provider.getName());
      }
    }
    finally {
      tracer.wayout();
    }
  }

  @Test
  public void example2() throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException, InvalidAlgorithmParameterException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "example2()");
    
    try {
      Provider provider = new de.christofreichardt.crypto.Provider();
      Security.addProvider(provider);
      try {
        File file = new File("../data/loremipsum.txt");
        byte[] bytes = Files.readAllBytes(file.toPath());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SchnorrSignature");
        SchnorrSigKeyGenParameterSpec schnorrSigGenParameterSpec = new SchnorrSigKeyGenParameterSpec(Strength.MINIMAL);
        keyPairGenerator.initialize(schnorrSigGenParameterSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        SchnorrPublicKey publicKey = (SchnorrPublicKey) keyPair.getPublic();
        
        tracer.out().printfIndentln("publicKey.getSchnorrParams().getQ().bitLength() = %d", publicKey.getSchnorrParams().getQ().bitLength());
        tracer.out().printfIndentln("publicKey.getSchnorrParams().getP().bitLength() = %d", publicKey.getSchnorrParams().getP().bitLength());
        
        assert publicKey.getSchnorrParams().getQ().bitLength() == 160;
        assert publicKey.getSchnorrParams().getP().bitLength() == 1024;
        
        Signature signature = Signature.getInstance("SchnorrSignatureWithSHA256");
        signature.initSign(keyPair.getPrivate());
        signature.update(bytes);
        byte[] signatureBytes = signature.sign();
        signature.initVerify(keyPair.getPublic());
        signature.update(bytes);
        boolean verified = signature.verify(signatureBytes);
        
        tracer.out().printfIndentln("verified = %b", verified);
        
        assert verified;
      }
      finally {
        Security.removeProvider(provider.getName());
      }
    }
    finally {
      tracer.wayout();
    }
  }
  
  @Test
  public void example3() throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException, InvalidAlgorithmParameterException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "example3()");
    
    try {
      Provider provider = new de.christofreichardt.crypto.Provider();
      Security.addProvider(provider);
      try {
        File file = new File("../data/loremipsum.txt");
        byte[] bytes = Files.readAllBytes(file.toPath());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SchnorrSignature");
        SchnorrSigKeyGenParameterSpec schnorrSigGenParameterSpec = new SchnorrSigKeyGenParameterSpec(Strength.STRONG);
        keyPairGenerator.initialize(schnorrSigGenParameterSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        SchnorrPublicKey publicKey = (SchnorrPublicKey) keyPair.getPublic();
        
        tracer.out().printfIndentln("publicKey.getSchnorrParams().getQ().bitLength() = %d", publicKey.getSchnorrParams().getQ().bitLength());
        tracer.out().printfIndentln("publicKey.getSchnorrParams().getP().bitLength() = %d", publicKey.getSchnorrParams().getP().bitLength());
        
        assert publicKey.getSchnorrParams().getQ().bitLength() == 1024;
        assert publicKey.getSchnorrParams().getP().bitLength() == 4096;
        
        Signature signature = Signature.getInstance("SchnorrSignatureWithSHA256");
        signature.initSign(keyPair.getPrivate());
        signature.update(bytes);
        byte[] signatureBytes = signature.sign();
        signature.initVerify(keyPair.getPublic());
        signature.update(bytes);
        boolean verified = signature.verify(signatureBytes);
        
        tracer.out().printfIndentln("verified = %b", verified);
        
        assert verified;
      }
      finally {
        Security.removeProvider(provider.getName());
      }
    }
    finally {
      tracer.wayout();
    }
  }
  
  @Test
  public void example4() throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException, InvalidAlgorithmParameterException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "example4()");
    
    try {
      Provider provider = new de.christofreichardt.crypto.Provider();
      Security.addProvider(provider);
      try {
        File file = new File("../data/loremipsum.txt");
        byte[] bytes = Files.readAllBytes(file.toPath());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SchnorrSignature");
        SchnorrSigKeyGenParameterSpec schnorrSigGenParameterSpec = new SchnorrSigKeyGenParameterSpec(1024, 256, false);
        keyPairGenerator.initialize(schnorrSigGenParameterSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        SchnorrPublicKey publicKey = (SchnorrPublicKey) keyPair.getPublic();
        
        tracer.out().printfIndentln("publicKey.getSchnorrParams().getQ().bitLength() = %d", publicKey.getSchnorrParams().getQ().bitLength());
        tracer.out().printfIndentln("publicKey.getSchnorrParams().getP().bitLength() = %d", publicKey.getSchnorrParams().getP().bitLength());
        
        assert publicKey.getSchnorrParams().getQ().bitLength() == 256;
        
        Signature signature = Signature.getInstance("SchnorrSignatureWithSHA256");
        signature.initSign(keyPair.getPrivate());
        signature.update(bytes);
        byte[] signatureBytes = signature.sign();
        signature.initVerify(keyPair.getPublic());
        signature.update(bytes);
        boolean verified = signature.verify(signatureBytes);
        
        tracer.out().printfIndentln("verified = %b", verified);
        
        assert verified;
      }
      finally {
        Security.removeProvider(provider.getName());
      }
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
