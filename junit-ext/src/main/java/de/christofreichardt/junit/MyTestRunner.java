/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package de.christofreichardt.junit;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import java.lang.reflect.Constructor;
import java.util.List;
import java.util.Properties;
import org.junit.runner.notification.RunNotifier;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.InitializationError;
import org.junit.runners.model.TestClass;

/**
 *
 * @author Developer
 */
public class MyTestRunner extends BlockJUnit4ClassRunner implements Traceable {
  
  final Properties properties;

  public MyTestRunner(Class<?> klass, Properties properties) throws InitializationError {
    super(klass);
    this.properties = properties;
  }
  
  @Override
  protected void validateConstructor(List<Throwable> errors) {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "validateConstructor(List<Throwable> errors)");

    try {
      tracer.out().printfIndentln("errors.size() = %d", errors.size());
      
      TestClass testClass = getTestClass();
      Constructor<?> constructor = testClass.getOnlyConstructor();
      Class<?>[] parameterTypes = constructor.getParameterTypes();
      if (parameterTypes.length != 1 || !"java.util.Properties".equals(parameterTypes[0].getName())) {
        errors.add(new IllegalArgumentException("Need a 'java.util.Properties' argument."));
      }
    }
    finally {
      tracer.wayout();
    }
  }
  
  @Override
  protected Object createTest() throws Exception {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("Object", this, "createTest()");

    try {
      tracer.out().printfIndentln("getTestClass().getName() = %s", getTestClass().getName());

      TestClass testClass = getTestClass();
      Constructor<?> constructor = testClass.getOnlyConstructor();
      Object[] args = {this.properties};
      Object object = constructor.newInstance(args);

      tracer.out().printfIndentln("object.hashCode() = %d", object.hashCode());

      return object;
    }
    finally {
      tracer.wayout();
    }
  }

  @Override
  public void run(RunNotifier notifier) {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "run(RunNotifier notifier)");

    try {
      super.run(notifier);
    }
    finally {
      tracer.wayout();
    }
  }

  @Override
  protected void runChild(FrameworkMethod frameworkMethod, RunNotifier notifier) {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "runChild(FrameworkMethod frameworkMethod, RunNotifier notifier)");

    try {
      tracer.out().printfIndentln("frameworkMethod.getName() = %s", frameworkMethod.getName());
      
      super.runChild(frameworkMethod, notifier);
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
