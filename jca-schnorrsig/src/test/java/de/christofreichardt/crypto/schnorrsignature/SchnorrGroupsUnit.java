/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package de.christofreichardt.crypto.schnorrsignature;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import java.math.BigInteger;
import java.util.Properties;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Christof Reichardt
 */
public class SchnorrGroupsUnit implements Traceable {
  final private Properties properties;

  public SchnorrGroupsUnit(Properties properties) {
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
  public void groupsWithDefaultStrength() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "groupsWithDefaultStrength()");
    
    try {
      for (SchnorrGroup schnorrGroup : SchnorrGroups.DEFAULT) {
        tracer.out().printfIndentln("schnorrGroup = %s", schnorrGroup);
        
        Assert.assertTrue("q | (p - 1) doesn't hold.", ((schnorrGroup.getP().subtract(BigInteger.ONE)).mod(schnorrGroup.getQ())).equals(BigInteger.ZERO));
        Assert.assertTrue("p expected to have " + SchnorrSigGenParameterSpec.L + " bits.", schnorrGroup.getP().bitLength() == SchnorrSigGenParameterSpec.L);
        Assert.assertTrue("q expected to have " + SchnorrSigGenParameterSpec.T + " bits.", schnorrGroup.getQ().bitLength() == SchnorrSigGenParameterSpec.T);
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
