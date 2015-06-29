/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package de.christofreichardt.crypto;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.DSAPrivateKey;
import java.util.Properties;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author Christof Reichardt
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
  public void dsaKeyPairGen() throws NoSuchAlgorithmException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "dsaKeyPairGen()");
    
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
      keyPairGenerator.initialize(1024);
      KeyPair keyPair = keyPairGenerator.genKeyPair();
      
      tracer.out().printfIndentln("keyPair.getPrivate().getClass().getName() = %s", keyPair.getPrivate().getClass().getName());
      tracer.out().printfIndentln("DSAPrivateKey.class.isAssignableFrom(%s) = %b", 
          keyPair.getPrivate().getClass().getName(), 
          DSAPrivateKey.class.isAssignableFrom(keyPair.getPrivate().getClass()));
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
