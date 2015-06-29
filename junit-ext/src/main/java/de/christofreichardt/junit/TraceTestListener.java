/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package de.christofreichardt.junit;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.LogLevel;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import org.junit.runner.Description;
import org.junit.runner.Result;
import org.junit.runner.notification.Failure;
import org.junit.runner.notification.RunListener;

/**
 *
 * @author Christof Reichardt
 */
public class TraceTestListener extends RunListener implements Traceable {

  @Override
  public void testFailure(Failure failure) throws Exception {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "testFailure(Failure failure)");

    try {
      super.testFailure(failure);
      tracer.out().printfIndentln("%s[failure.getException() = %s]", failure.getDescription().getDisplayName(), failure.getException());
    }
    finally {
      tracer.wayout();
    }
  }

  @Override
  public void testFinished(Description description) throws Exception {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "testFinished(Description description)");

    try {
      tracer.out().printfIndentln("description.getDisplayName() = %s", description.getDisplayName());
      traceMemory();
      
      super.testFinished(description);
    }
    finally {
      tracer.wayout();
    }
  }

  @Override
  public void testRunFinished(Result result) throws Exception {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "testRunFinished(Result result)");

    try {
      super.testRunFinished(result);
    }
    finally {
      tracer.wayout();
    }
  }

  @Override
  public void testRunStarted(Description description) throws Exception {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "testRunStarted(Description description)");

    try {
      traceDescription(description);
      super.testRunStarted(description);
    }
    finally {
      tracer.wayout();
    }
  }

  @Override
  public void testStarted(Description description) throws Exception {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "testStarted(Description description)");

    try {
      tracer.logMessage(LogLevel.INFO, "'" + description.getDisplayName() + "' started ...", getClass(), "testStarted(Description description)");
      
      System.runFinalization();
      System.gc();
      traceMemory();
      
      super.testStarted(description);
    }
    finally {
      tracer.wayout();
    }
  }

  private void traceDescription(Description description) {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "traceDescription(Description description)");

    try {
      tracer.out().printfIndentln("description.getDisplayName() = %s", description.getDisplayName());
      if (description.isSuite()) {
        tracer.out().printfIndentln("description.testCount() = %d", description.testCount());

        for (Description child : description.getChildren()) {
          traceDescription(child);
        }
      }
    }
    finally {
      tracer.wayout();
    }
  }
  
  private void traceMemory() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "traceMemory()");

    try {
      tracer.out().printfIndentln("Free: %d KB", Runtime.getRuntime().freeMemory()/1024);
      tracer.out().printfIndentln("Total: %d KB", Runtime.getRuntime().totalMemory()/1024);
      tracer.out().printfIndentln("Max: %d KB", Runtime.getRuntime().maxMemory()/1024);
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
