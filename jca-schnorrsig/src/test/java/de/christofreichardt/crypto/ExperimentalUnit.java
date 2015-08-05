/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package de.christofreichardt.crypto;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.DSAPrivateKey;
import java.util.Arrays;
import java.util.Properties;
import java.util.Random;

import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;

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
  
  @Test
  public void randomBytes() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "randomBytes()");
    
    try {
      final int NUMBER_OF_BYTES = 128;
      byte[] randomBytes = new byte[NUMBER_OF_BYTES];
      SecureRandom secureRandom = new SecureRandom();
      secureRandom.nextBytes(randomBytes);
      tracer.out().printIndent("randomBytes: ");
      for (byte randomByte : randomBytes) {
        tracer.out().print(randomByte + " ");
      }
      tracer.out().println();
    }
    finally {
      tracer.wayout();
    }
  }
  
  @Test
  public void distribution_8bit() throws NoSuchAlgorithmException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "distribution_8bit()");
    
    try {
      BigInteger[] primes = {BigInteger.valueOf(131), BigInteger.valueOf(193), BigInteger.valueOf(251)};
      int[][] distributions = new int[primes.length][];
      final int TESTS = 10000000;
      Random random = new Random();
      
      for (int i=0; i<primes.length; i++) {
        distributions[i] = new int[primes[i].intValue()];
        Arrays.fill(distributions[i], 0);
        for (int j=0; j<TESTS; j++) {
          byte[] randomBytes = new byte[2];
          random.nextBytes(randomBytes);
          BigInteger hash = new BigInteger(randomBytes);
          int index = hash.mod(primes[i]).intValue();
          distributions[i][index]++;
        }
        
        int maxDeviation = 0, mean = TESTS/primes[i].intValue();
        tracer.out().printfIndentln("--> distribution(%s), mean = %d", primes[i], mean);
        tracer.out().printIndentString();
        for (int index=0; index<primes[i].intValue(); index++) {
          tracer.out().printf("%04d ", distributions[i][index]);
          int deviation = Math.abs(mean - distributions[i][index]);
          if (deviation > maxDeviation)
            maxDeviation = deviation;
        }
        tracer.out().println();
        int percentage = maxDeviation/(mean/100);
        tracer.out().printfIndentln("maxDeviation = %d, (%d%%)", maxDeviation, percentage);
      }
    }
    finally {
      tracer.wayout();
    }
  }
  
  @Ignore
  public void distribution_16bit() throws NoSuchAlgorithmException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "distribution_16bit()");
    
    try {
      BigInteger[] primes = {BigInteger.valueOf(32771), BigInteger.valueOf(49157), BigInteger.valueOf(65521)};
      long[][] distributions = new long[primes.length][];
      final long TESTS = 100000000;
      Random random = new Random();
      
      for (int i=0; i<primes.length; i++) {
        distributions[i] = new long[primes[i].intValue()];
        Arrays.fill(distributions[i], 0);
        for (int j=0; j<TESTS; j++) {
          BigInteger hash = new BigInteger(2*16, random);
          int index = hash.mod(primes[i]).intValue();
          distributions[i][index]++;
        }
        
        long maxDeviation = 0, mean = TESTS/primes[i].intValue();
        tracer.out().printfIndentln("--> distribution(%s), mean = %d", primes[i], mean);
        tracer.out().printIndentString();
        for (int index=0; index<primes[i].intValue(); index++) {
          tracer.out().printf("%04d ", distributions[i][index]);
          long deviation = Math.abs(mean - distributions[i][index]);
          if (deviation > maxDeviation)
            maxDeviation = deviation;
        }
        tracer.out().println();
        tracer.out().printfIndentln("maxDeviation = %d", maxDeviation);
      }
    }
    finally {
      tracer.wayout();
    }
  }
  
  @Test
  public void passwordBasedEncryption() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "passwordBasedEncryption()");
    
    try {
    }
    finally {
      tracer.wayout();
    }
  }
  
  @Test
  public void unsignedBigInteger() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "unsignedBigInteger()");
    
    try {
      byte[] nBytes = {(byte) 167, (byte) 156};
      BigInteger n = new BigInteger(1, nBytes);
      
      tracer.out().printfIndentln("n = %s", n);
      tracer.out().printfIndentln("--- nBytes(%d) ---", n.toByteArray().length);
      traceBytes(n.toByteArray());
      
      BigInteger m = new BigInteger(n.toByteArray());
      
      tracer.out().printfIndentln("m = %s", m);
      tracer.out().printfIndentln("--- mBytes(%d) ---", m.toByteArray().length);
      traceBytes(m.toByteArray());
    }
    finally {
      tracer.wayout();
    }
  }
  
  protected void traceBytes(byte[] bytes) {
    AbstractTracer tracer = getCurrentTracer();
    for (int i=0; i<bytes.length; i++) {
      if (i % 16 == 0) {
        if (i != 0)
          tracer.out().println();
        tracer.out().printIndentString();
      }
      tracer.out().printf("%3d ", bytes[i] & 255);
    }
    tracer.out().println();
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
