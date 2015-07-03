package de.christofreichardt.crypto.ecschnorrsignature;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Properties;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;

public class SignatureUnit implements Traceable {
  final private Properties properties;
  private byte[] msgBytes;

  public SignatureUnit(Properties properties) {
    this.properties = properties;
  }
  
  @Before
  public void init() throws IOException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "init()");
    
    try {
      this.msgBytes = loadMsgBytes();
    }
    finally {
      tracer.wayout();
    }
  }
  
  private byte[] loadMsgBytes() throws IOException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("byte[]", this, "loadMsgBytes()");
    
    try {
      File blindTextFile = new File(this.properties.getProperty("de.christofreichardt.crypto.schnorrsignature.SignatureUnit.blindtext", 
          "./data/loremipsum.txt"));
      byte[] bytes = Files.readAllBytes(blindTextFile.toPath());
      traceMsgBytes(bytes);
      return bytes;
    }
    finally {
      tracer.wayout();
    }
  }
  
  private void traceMsgBytes(byte[] bytes) {
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
  
  
  @Test
  public void plainUse() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "plainUse()");
    
    try {
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
