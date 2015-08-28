package de.christofreichardt.crypto.ecschnorrsignature;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Map.Entry;
import java.util.Properties;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import de.christofreichardt.crypto.Provider;
import de.christofreichardt.crypto.ecschnorrsignature.ECSchnorrSigKeyGenParameterSpec.CurveCompilation;
import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import de.christofreichardt.scala.ellipticcurve.GroupLaw.Element;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesWithPrimeField.AffineCurve;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesWithPrimeField.AffinePoint;
import de.christofreichardt.scala.ellipticcurve.affine.ShortWeierstrass;

public class ECSchnorrKeyPairGeneratorUnit implements Traceable {
  public final static int DEFAULT_KEYSIZE = 256;
  final private Properties properties;
  final String ALGORITHM_NAME = "ECSchnorrSignature";
  final Provider provider = new Provider();

  public ECSchnorrKeyPairGeneratorUnit(Properties properties) {
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
  public void nistCurves() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "nistCurves()");
    
    try {
      for (Entry<String, CurveSpec> entry : NIST.curves.entrySet()) {
        String curveId = entry.getKey();
        CurveSpec curveSpec = entry.getValue();
        AffineCurve curve = curveSpec.getCurve();
        AffinePoint point = curve.randomPoint();
        
        tracer.out().printfIndentln("curve(%s) = %s", curveId, curve);
        tracer.out().printfIndentln("point = %s", point);
        
        Element element = point.multiply(curveSpec.getOrder());
        
        tracer.out().printfIndentln("element = %s", element);
        Assert.assertTrue("Expected the NeutralElement.", element.isNeutralElement());
        
        AffinePoint basePoint = curveSpec.getgPoint();
        
        tracer.out().printfIndentln("basePoint = %s", basePoint);
        Assert.assertTrue("Expected a valid point.", curve.isValidPoint(basePoint));
        
        element = basePoint.multiply(curveSpec.getOrder());
        
        tracer.out().printfIndentln("element = %s", element);
        Assert.assertTrue("Expected the NeutralElement.", element.isNeutralElement());
      }
    }
    finally {
      tracer.wayout();
    }
  }
  
  @Test
  public void defaultParams() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "defaultParams()");
    
    try {
      KeyPairGenerator keyPairGenerator = new KeyPairGenerator();
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      validateKeyPair(keyPair, DEFAULT_KEYSIZE);
    }
    finally {
      tracer.wayout();
    }
  }
  
  @Test
  public void customKeySizes() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "customKeySizes()");
    
    try {
      int[] keySizes = {160, 192, 224, 256, 320, 384, 512};
      KeyPairGenerator keyPairGenerator = new KeyPairGenerator();
      for (int keySize : keySizes) {
        keyPairGenerator.initialize(keySize, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        validateKeyPair(keyPair, keySize);
      }
    }
    finally {
      tracer.wayout();
    }
  }
  
  @Test
  public void customParams() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "customParams()");

    try {
      java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance(ALGORITHM_NAME);
      
      for (String curveId : NIST.curveIds) {
        ECSchnorrSigKeyGenParameterSpec ecSchnorrSigKeyGenParameterSpec = new ECSchnorrSigKeyGenParameterSpec(CurveCompilation.NIST, curveId, true);
        
        tracer.out().printfIndentln("ecSchnorrSigKeyGenParameterSpec = %s", ecSchnorrSigKeyGenParameterSpec);
        
        keyPairGenerator.initialize(ecSchnorrSigKeyGenParameterSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        validateKeyPair(keyPair, NIST.curves.get(curveId).getCurve().p().bitLength());
      }
      
      for (String curveId : NIST.curveIds) {
        ECSchnorrSigKeyGenParameterSpec ecSchnorrSigKeyGenParameterSpec = new ECSchnorrSigKeyGenParameterSpec(CurveCompilation.NIST, curveId);
        
        tracer.out().printfIndentln("ecSchnorrSigKeyGenParameterSpec = %s", ecSchnorrSigKeyGenParameterSpec);
        
        keyPairGenerator.initialize(ecSchnorrSigKeyGenParameterSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        validateKeyPair(keyPair, NIST.curves.get(curveId).getCurve().p().bitLength());
      }
      
      for (String curveId : BrainPool.curveIds) {
        ECSchnorrSigKeyGenParameterSpec ecSchnorrSigKeyGenParameterSpec = new ECSchnorrSigKeyGenParameterSpec(CurveCompilation.BRAINPOOL, curveId, true);
        
        tracer.out().printfIndentln("ecSchnorrSigKeyGenParameterSpec = %s", ecSchnorrSigKeyGenParameterSpec);
        
        keyPairGenerator.initialize(ecSchnorrSigKeyGenParameterSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        validateKeyPair(keyPair, BrainPool.curves.get(curveId).getCurve().p().bitLength());
      }
      
      for (String curveId : BrainPool.curveIds) {
        ECSchnorrSigKeyGenParameterSpec ecSchnorrSigKeyGenParameterSpec = new ECSchnorrSigKeyGenParameterSpec(CurveCompilation.BRAINPOOL, curveId);
        
        tracer.out().printfIndentln("ecSchnorrSigKeyGenParameterSpec = %s", ecSchnorrSigKeyGenParameterSpec);
        
        keyPairGenerator.initialize(ecSchnorrSigKeyGenParameterSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        validateKeyPair(keyPair, BrainPool.curves.get(curveId).getCurve().p().bitLength());
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
      validateKeyPair(keyPair, DEFAULT_KEYSIZE);
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
      validateKeyPair(keyPair, DEFAULT_KEYSIZE);
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
      validateKeyPair(keyPair, DEFAULT_KEYSIZE);
    }
    finally {
      tracer.wayout();
    }
  }
  
  private void validateKeyPair(KeyPair keyPair, int expectedBitLength) {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "validateKeyPair(KeyPair keyPair)");
    
    try {
      tracer.out().printfIndentln("keyPair.getPrivate() = %s", keyPair.getPrivate());
      tracer.out().printfIndentln("keyPair.getPublic() = %s", keyPair.getPublic());
      
      Assert.assertTrue("Expected a SchnorrPrivateKey instance.", keyPair.getPrivate() instanceof ECSchnorrPrivateKey);
      Assert.assertTrue("Expected a SchnorrPublicKey instance.", keyPair.getPublic() instanceof ECSchnorrPublicKey);
      
      ECSchnorrPrivateKey ecSchnorrPrivateKey = (ECSchnorrPrivateKey) keyPair.getPrivate();
      ECSchnorrPublicKey ecSchnorrPublicKey = (ECSchnorrPublicKey) keyPair.getPublic();
      ECSchnorrParams ecSchnorrParams = ecSchnorrPrivateKey.getEcSchnorrParams();
      
      Assert.assertTrue("Expected the same ECSchnorrParams instance.", ecSchnorrParams == ecSchnorrPublicKey.getEcSchnorrParams());
      final int CERTAINTY = 100;
      Assert.assertTrue("Expected a prime group order.", ecSchnorrParams.getCurveSpec().getOrder().isProbablePrime(CERTAINTY));
      tracer.out().printfIndentln("ecSchnorrParams.getCurveSpec().getCurve().p().bitLength() = %d", ecSchnorrParams.getCurveSpec().getCurve().p().bitLength());
      Assert.assertTrue("Wrong keysize.", ecSchnorrParams.getCurveSpec().getCurve().p().bitLength() == expectedBitLength);
      
      Element element = ecSchnorrParams.getgPoint().multiply(ecSchnorrPrivateKey.getX());
      AffinePoint hPoint = ShortWeierstrass.elemToAffinePoint(element);
      
      Assert.assertTrue("Expected the public h point.", hPoint.equals(ecSchnorrPublicKey.gethPoint()));
    }
    finally {
      tracer.wayout();
    }
  }
  
  @Test
  public void brainPoolCurves() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "brainPoolCurves()");
    
    try {
      for (Entry<String, CurveSpec> entry : BrainPool.curves.entrySet()) {
        String curveId = entry.getKey();
        CurveSpec curveSpec = entry.getValue();
        AffineCurve curve = curveSpec.getCurve();
        AffinePoint point = curve.randomPoint();
        
        tracer.out().printfIndentln("curve(%s) = %s", curveId, curve);
        tracer.out().printfIndentln("point = %s", point);
        
        Element element = point.multiply(curveSpec.getOrder());
        
        tracer.out().printfIndentln("element = %s", element);
        Assert.assertTrue("Expected the NeutralElement.", element.isNeutralElement());
        
        AffinePoint basePoint = curveSpec.getgPoint();
        
        tracer.out().printfIndentln("basePoint = %s", basePoint);
        Assert.assertTrue("Expected a valid point.", curve.isValidPoint(basePoint));
        
        element = basePoint.multiply(curveSpec.getOrder());
        
        tracer.out().printfIndentln("element = %s", element);
        Assert.assertTrue("Expected the NeutralElement.", element.isNeutralElement());
      }
    }
    finally {
      tracer.wayout();
    }
  }
  
  @Test
  public void safeCurves() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "safeCurves()");
    
    try {
      for (Entry<String, CurveSpec> entry : SafeCurves.curves.entrySet()) {
        String curveId = entry.getKey();
        CurveSpec curveSpec = entry.getValue();
        AffineCurve curve = curveSpec.getCurve();
        
        AffinePoint basePoint = curveSpec.getgPoint();
        
        tracer.out().printfIndentln("basePoint = %s", basePoint);
        Assert.assertTrue("Expected a valid point.", curve.isValidPoint(basePoint));
        
        Element element = basePoint.multiply(curveSpec.getOrder());
        
        tracer.out().printfIndentln("element = %s", element);
        Assert.assertTrue("Expected the NeutralElement.", element.isNeutralElement());
      }
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
