/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.christofreichardt.crypto;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesOddCharacteristic;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesOddCharacteristic.AffinePoint;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesOddCharacteristic.OddCharCoefficients;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesOddCharacteristic.PrimeField;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesOddCharacteristic.AffineCurve;

import java.math.BigInteger;
import java.util.Properties;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import scala.math.BigInt;

/**
 *
 * @author developer
 */
public class ExperimentalUnit implements Traceable {
  final private Properties properties;

  public ExperimentalUnit(Properties properties) {
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
  public void experiment() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "experiment()");

    try {
      BigInteger a = new BigInteger("42513");
      BigInteger b = new BigInteger("20792");
      BigInteger p = new BigInteger("93139");
      OddCharCoefficients coefficients = new OddCharCoefficients(new BigInt(a), new BigInt(b));
      PrimeField primeField = new PrimeField(new BigInt(p));
      AffineCurve curve = AffineCoordinatesOddCharacteristic.makeCurve(coefficients, primeField);
      AffinePoint point = curve.randomPoint();
      
      tracer.out().printfIndentln("curve = %s", curve);
      tracer.out().printfIndentln("point = %s", point);
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
