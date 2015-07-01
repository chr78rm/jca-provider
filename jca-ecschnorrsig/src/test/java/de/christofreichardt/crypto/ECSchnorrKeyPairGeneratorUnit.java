package de.christofreichardt.crypto;

import java.security.KeyPair;
import java.util.Map.Entry;
import java.util.Properties;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import scala.math.BigInt;
import de.christofreichardt.crypto.ecschnorrsignature.CurveSpec;
import de.christofreichardt.crypto.ecschnorrsignature.KeyPairGenerator;
import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import de.christofreichardt.scala.ellipticcurve.GroupLaw.Element;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesOddCharacteristic.AffineCurve;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesOddCharacteristic.AffinePoint;

public class ECSchnorrKeyPairGeneratorUnit implements Traceable {
  final private Properties properties;

  public ECSchnorrKeyPairGeneratorUnit(Properties properties) {
    this.properties = properties;
  }
  
  @Before
  public void init() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "init()");
    
    try {
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
      for (Entry<Integer, CurveSpec> entry : KeyPairGenerator.nistCurves.entrySet()) {
        int keySize = entry.getKey();
        CurveSpec curveSpec = entry.getValue();
        AffineCurve curve = curveSpec.getCurve();
        AffinePoint point = curve.randomPoint();
        
        tracer.out().printfIndentln("curve(%d) = %s", keySize, curve);
        tracer.out().printfIndentln("point = %s", point);
        
        Element element = point.multiply(new BigInt(curveSpec.getOrder()));
        
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
      
      tracer.out().printfIndentln("keyPair.getPrivate() = %s", keyPair.getPrivate());
      tracer.out().printfIndentln("keyPair.getPublic() = %s", keyPair.getPublic());
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
