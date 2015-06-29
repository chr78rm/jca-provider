/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package de.christofreichardt.junit;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.FileSystems;
import java.util.Properties;
import org.junit.runner.Description;
import org.junit.runner.Runner;
import org.junit.runner.notification.RunNotifier;
import org.junit.runners.Suite;
import org.junit.runners.model.InitializationError;

/**
 *
 * @author Christof Reichardt
 */
public class MySuite extends Runner implements Traceable {
  
  final private Suite suite;

  public MySuite(Class<?> testClass) throws InitializationError {
    try {
      initTracerFactory();
      this.suite = new Suite(testClass, new MyRunnerBuilder(readProperties()));
    }
    catch (TracerFactory.Exception | IOException ex) {
      throw new InitializationError(ex);
    }
  }
  
  private void initTracerFactory() throws TracerFactory.Exception {
    TracerFactory.getInstance().reset();
    InputStream resourceAsStream = MySuite.class.getClassLoader().getResourceAsStream("de/christofreichardt/junit/TraceConfig.xml");
    if (resourceAsStream != null) {
      TracerFactory.getInstance().readConfiguration(resourceAsStream);
    }
    TracerFactory.getInstance().openPoolTracer();
    TracerFactory.getInstance().getCurrentPoolTracer().initCurrentTracingContext();
  }
  
  private Properties readProperties() throws IOException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("Properties", this, "readProperties()");
    
    try {
      Properties properties = new Properties();
      File propertiesFile = FileSystems.getDefault().getPath(".", "test.properties").toFile();
      try (FileInputStream fileInputStream = new FileInputStream(propertiesFile)) {
        properties.load(fileInputStream);
      }
      for (String propertyName : properties.stringPropertyNames()) {
        tracer.out().printfIndentln("%s = %s", propertyName, properties.getProperty(propertyName));
      }
      return properties;
    }
    finally {
      tracer.wayout();
    }
  }

  @Override
  public void run(RunNotifier runNotifier) {
    try {
      AbstractTracer tracer = getCurrentTracer();
      tracer.entry("void", this, "run(RunNotifier runNotifier)");
    
      try {
        this.suite.run(runNotifier);
      }
      finally {
        tracer.wayout();
      }
    }
    finally {
      TracerFactory.getInstance().closePoolTracer();
    }
  }

  @Override
  public Description getDescription() {
    return this.suite.getDescription();
  }
  
  @Override
  public AbstractTracer getCurrentTracer() {
    return TracerFactory.getInstance().getCurrentPoolTracer();
  }
}
