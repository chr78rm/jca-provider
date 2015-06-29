/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package de.christofreichardt.junit;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import java.util.Properties;
import org.junit.runner.Runner;
import org.junit.runners.model.RunnerBuilder;

/**
 *
 * @author Christof Reichardt
 */
public class MyRunnerBuilder extends RunnerBuilder implements Traceable {
  
  final private Properties properties;

  public MyRunnerBuilder(Properties properties) {
    this.properties = properties;
  }
  
  @Override
  public Runner runnerForClass(Class<?> klass) throws Throwable {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("Runner", this, "runnerForClass(Class<?> klass)");

    try {
      tracer.out().printfIndentln("klass.getName() = %s", klass.getName());
      
      return new MyTestRunner(klass, this.properties);
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
