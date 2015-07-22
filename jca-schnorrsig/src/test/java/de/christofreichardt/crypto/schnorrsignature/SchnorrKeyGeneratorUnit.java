/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package de.christofreichardt.crypto.schnorrsignature;

import de.christofreichardt.crypto.Provider;
import de.christofreichardt.crypto.schnorrsignature.SchnorrSigKeyGenParameterSpec.Strength;
import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.EnumSet;
import java.util.Properties;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

/**
 *
 * @author Christof Reichardt
 */
public class SchnorrKeyGeneratorUnit implements Traceable {
  
  final private Properties properties;
  
  final String ALGORITHM_NAME = "SchnorrSignature";
  final Provider provider = new Provider();

  public SchnorrKeyGeneratorUnit(Properties properties) {
    this.properties = properties;
  }
  
  @Before
  public void init() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "init()");
    
    try {
      Security.addProvider(this.provider);
    }
    finally {
      tracer.wayout();
    }
  }
  
  @Test
  public void customValidSecParams() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "customValidSecParams()");
    
    try {
      SchnorrSigKeyGenParameterSpec[] specs = {
        new SchnorrSigKeyGenParameterSpec(1024, 160, false),
        new SchnorrSigKeyGenParameterSpec(2048, 512, false),
//        new SchnorrSigKeyGenParameterSpec(4096, 1024, false),
      };
      for (SchnorrSigKeyGenParameterSpec schnorrSigGenParameterSpec : specs) {
        tracer.out().printfIndentln("schnorrSigGenParameterSpec = %s", schnorrSigGenParameterSpec);

        KeyPairGenerator keyPairGenerator = new KeyPairGenerator();
        keyPairGenerator.initialize(schnorrSigGenParameterSpec, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        validateKeyPair(keyPair);
      }
    }
    finally {
      tracer.wayout();
    }
  }
  
  @Test
  public void defaultSecParams() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "defaultSecParams()");
    
    try {
      KeyPairGenerator keyPairGenerator = new KeyPairGenerator();
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      validateKeyPair(keyPair);
    }
    finally {
      tracer.wayout();
    }
  }
  
  @Test
  public void predefinedStrengths() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "predefinedStrengths()");
    
    try {
      java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance(ALGORITHM_NAME);
      
      EnumSet<Strength> strengths = EnumSet.allOf(Strength.class);
      for (Strength strength : strengths) {
        if (strength != Strength.CUSTOM) {
          tracer.out().printfIndentln("strength = %s", strength);
          SchnorrSigKeyGenParameterSpec schnorrSigGenParameterSpec = new SchnorrSigKeyGenParameterSpec(strength);
          keyPairGenerator.initialize(schnorrSigGenParameterSpec);
          KeyPair keyPair = keyPairGenerator.generateKeyPair();
          validateKeyPair(keyPair);
        }
      }
    }
    finally {
      tracer.wayout();
    }
  }
  
  @Test
  public void providerByAlgorithmName() throws NoSuchAlgorithmException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "providerByAlgorithmName()");
    
    try {
      java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance(ALGORITHM_NAME);
      
      Assert.assertTrue("Expected a keyPairGenerator for the " + ALGORITHM_NAME + ".", keyPairGenerator.getAlgorithm().equals(ALGORITHM_NAME));
      
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      validateKeyPair(keyPair);
    }
    finally {
      tracer.wayout();
    }
  }
  
  @Test
  public void providerByAlgorithmAndProvidername() throws NoSuchAlgorithmException, NoSuchProviderException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "providerByAlgorithmAndProvidername()");
    
    try {
      java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance(ALGORITHM_NAME, Provider.NAME);
      
      Assert.assertTrue("Expected a keyPairGenerator for the " + ALGORITHM_NAME + ".", keyPairGenerator.getAlgorithm().equals(ALGORITHM_NAME));
      Assert.assertTrue("Expected a keyPairGenerator from the " + Provider.NAME + ".", keyPairGenerator.getProvider().getName().equals(Provider.NAME));
      
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      validateKeyPair(keyPair);
    }
    finally {
      tracer.wayout();
    }
  }
  
  @Test
  public void providerByAlgorithmAndProvider() throws NoSuchAlgorithmException, NoSuchProviderException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "providerByAlgorithmAndProvider()");
    
    try {
      java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance(ALGORITHM_NAME, this.provider);
      
      Assert.assertTrue("Expected a keyPairGenerator for the " + ALGORITHM_NAME + ".", keyPairGenerator.getAlgorithm().equals(ALGORITHM_NAME));
      Assert.assertTrue("Expected a keyPairGenerator from the " + Provider.NAME + ".", keyPairGenerator.getProvider().getName().equals(Provider.NAME));
      
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      validateKeyPair(keyPair);
    }
    finally {
      tracer.wayout();
    }
  }
  
  private void validateKeyPair(KeyPair keyPair) {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "validateKeyPair(KeyPair keyPair)");
    
    try {
      tracer.out().printfIndentln("keyPair.getPrivate() = %s", keyPair.getPrivate());
      tracer.out().printfIndentln("keyPair.getPublic() = %s", keyPair.getPublic());
      
      Assert.assertTrue("Expected a SchnorrPrivateKey instance.", keyPair.getPrivate() instanceof SchnorrPrivateKey);
      Assert.assertTrue("Expected a SchnorrPublicKey instance.", keyPair.getPublic() instanceof SchnorrPublicKey);
      
      SchnorrPublicKey schnorrPublicKey = (SchnorrPublicKey) keyPair.getPublic();
      SchnorrPrivateKey schnorrPrivateKey = (SchnorrPrivateKey) keyPair.getPrivate();
      SchnorrParams schnorrParams = schnorrPrivateKey.getSchnorrParams();
      
      Assert.assertTrue("Expected the same SchnorrParams instance.", schnorrParams == schnorrPublicKey.getSchnorrParams());
      Assert.assertTrue("q must be prime.", schnorrParams.getQ().isProbablePrime(KeyPairGenerator.CERTAINTY));
      Assert.assertTrue("p must be prime.", schnorrParams.getP().isProbablePrime(KeyPairGenerator.CERTAINTY));
      Assert.assertTrue("q | (p - 1) doesn't hold.", (schnorrParams.getP().subtract(BigInteger.ONE)).mod(schnorrParams.getQ()).equals(BigInteger.ZERO));
      Assert.assertTrue("h == g^x (mod p) violated.", schnorrParams.getG().modPow(schnorrPrivateKey.getX(), schnorrParams.getP()).equals(schnorrPublicKey.getH()));
    }
    finally {
      tracer.wayout();
    }
  }
  
  @After
  public void exit() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "exit()");
    
    try {
      Security.removeProvider(Provider.NAME);
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
