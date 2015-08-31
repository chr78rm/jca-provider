package de.christofreichardt.scala.ellipticcurve

import de.christofreichardt.diagnosis.AbstractTracer
import de.christofreichardt.diagnosis.TracerFactory
import de.christofreichardt.scala.diagnosis.Tracing

import java.io.BufferedInputStream
import java.io.File
import java.io.FileInputStream
import java.util.Scanner


/**
 * @author Christof Reichardt
 */
object PrimeBase extends Tracing {
  val primeBaseFile: File = new File("." + File.separator + "data" + File.separator + "PrimeBase.txt")
  require(primeBaseFile.exists())
  val primes = init()
  
  class BufferedPrimeScanner(bufferedInputStream : BufferedInputStream) extends Iterator[Int] {
    val scanner = new Scanner(bufferedInputStream)
    val tracer = getCurrentTracer
    tracer.out().printfIndentln("scanner.radix() = %d", int2Integer(scanner.radix()))
    def hasNext: Boolean = scanner.hasNextInt()
    def next: Int = scanner.nextInt()
  }
  
  private def init(): IndexedSeq[Int] = {
    withTracer("IndexedSeq[Int]", this, "init()") {
      val buffer = new BufferedInputStream(new FileInputStream(primeBaseFile))
      try {
        val primeScanner = new BufferedPrimeScanner(buffer)
        primeScanner.toIndexedSeq
      }
      finally {
        buffer.close()
      }
    }
  }
  
  override def getCurrentTracer(): AbstractTracer = {
    try {
      TracerFactory.getInstance().getDefaultTracer
    }
    catch {
      case ex: TracerFactory.Exception => TracerFactory.getInstance().getDefaultTracer
    }
  }
}