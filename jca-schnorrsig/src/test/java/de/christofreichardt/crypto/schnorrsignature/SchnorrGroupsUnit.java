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
        Assert.assertTrue("p expected to have " + SchnorrSigKeyGenParameterSpec.L + " bits.", schnorrGroup.getP().bitLength() == SchnorrSigKeyGenParameterSpec.L);
        Assert.assertTrue("q expected to have " + SchnorrSigKeyGenParameterSpec.T + " bits.", schnorrGroup.getQ().bitLength() == SchnorrSigKeyGenParameterSpec.T);
      }
    }
    finally {
      tracer.wayout();
    }
  }
  
  @Test
  public void groupsWithMinimalStrength() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "groupsWithMinimalStrength()");
    
    try {
      for (SchnorrGroup schnorrGroup : SchnorrGroups.MINIMAL) {
        tracer.out().printfIndentln("schnorrGroup = %s", schnorrGroup);
        
        Assert.assertTrue("q | (p - 1) doesn't hold.", ((schnorrGroup.getP().subtract(BigInteger.ONE)).mod(schnorrGroup.getQ())).equals(BigInteger.ZERO));
        Assert.assertTrue("p expected to have " + SchnorrSigKeyGenParameterSpec.L_MINIMAL + " bits.", schnorrGroup.getP().bitLength() == SchnorrSigKeyGenParameterSpec.L_MINIMAL);
        Assert.assertTrue("q expected to have " + SchnorrSigKeyGenParameterSpec.T_MINIMAL + " bits.", schnorrGroup.getQ().bitLength() == SchnorrSigKeyGenParameterSpec.T_MINIMAL);
      }
    }
    finally {
      tracer.wayout();
    }
  }
  
  @Test
  public void groupsWithStrongStrength() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "groupsWithStrongStrength()");
    
    try {
      final int EPSILON = 5;
      for (SchnorrGroup schnorrGroup : SchnorrGroups.STRONG) {
        tracer.out().printfIndentln("schnorrGroup = %s", schnorrGroup);
        
        Assert.assertTrue("q | (p - 1) doesn't hold.", ((schnorrGroup.getP().subtract(BigInteger.ONE)).mod(schnorrGroup.getQ())).equals(BigInteger.ZERO));
        Assert.assertTrue("p expected to have at least " + (SchnorrSigKeyGenParameterSpec.L_STRONG - EPSILON) + " bits.", schnorrGroup.getP().bitLength() >= SchnorrSigKeyGenParameterSpec.L_STRONG - EPSILON);
        Assert.assertTrue("q expected to have " + SchnorrSigKeyGenParameterSpec.T_STRONG + " bits.", schnorrGroup.getQ().bitLength() == SchnorrSigKeyGenParameterSpec.T_STRONG);
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
