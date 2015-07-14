package de.christofreichardt.scala.ellipticcurve

package affine {

  import de.christofreichardt.diagnosis.AbstractTracer
  import de.christofreichardt.diagnosis.TracerFactory
  import de.christofreichardt.scala.diagnosis.Tracing

  import scala.BigInt
  import scala.Stream
  import scala.annotation.tailrec

  import ShortWeierstrass.NeutralElement
  import ShortWeierstrass.PointMultiplication
  import ShortWeierstrass.AffinePoint
  import ShortWeierstrass.Element

  class BinaryMethod extends PointMultiplication with Tracing {
    def multiply(m: BigInt, point: AffinePoint): Element = {
      val tracer = getCurrentTracer()
      withTracer("Element", this, "multiply(m: BigInt, point: AffinePoint)") {
        tracer.out().printfIndentln("m = %s", m)
        tracer.out().printfIndentln("point = %s", point)

        @tailrec
        def multiply(q: Element, i: Int): Element = {
          tracer.out().printfIndentln("i = %d", int2Integer(i))
          tracer.out().printfIndentln("q = %s", q)
          tracer.out().flush()

          if (i == 0) {
            q
          }
          else {
            val double = q.add(q)
            val sum =
              if (m.testBit(i - 1)) double add point
              else double
            multiply(sum, i - 1)
          }
        }

        if (m == BigInt(0)) new NeutralElement
        else multiply(new NeutralElement, m.bitLength)
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

  class FixedPointBinaryMethod(val fixedPoint: ShortWeierstrass.AffinePoint)
      extends ShortWeierstrass.PointMultiplication with Tracing {

    def twoPowerPointStream: Stream[(Int, Element)] = {
      def pointStream(exp: Int, power: BigInt, element: Element): Stream[(Int, Element)] = {
        if (exp == 0) Stream.cons((exp, this.fixedPoint), pointStream(1, BigInt(1), this.fixedPoint))
        else if (exp == 1) {
          val nextPoint = this.fixedPoint add this.fixedPoint
          Stream.cons((exp, nextPoint), pointStream(2, BigInt(2), nextPoint))
        }
        else {
          val nextPower = power*BigInt(2)
          if (nextPower < this.fixedPoint.curve.p*2) {
            val nextPoint = element add element
            Stream.cons((exp, nextPoint), pointStream(exp + 1, nextPower, nextPoint))
          }
          else 
            Stream.empty[(Int, Element)]
        }
      }
      pointStream(0, BigInt(1), this.fixedPoint)
    }
    
    val multiplies = twoPowerPointStream.toIndexedSeq

    def multiply(m: BigInt, point: AffinePoint): Element = {
      require(point == this.fixedPoint, "Multiplication is fixed.")
      
      withTracer("Element", this, "multiply(m: BigInt, point: AffinePoint)") {
        val tracer = getCurrentTracer
        tracer.out().printfIndentln("m(%d) = %s", m.bitLength: Integer, m)

        @tailrec
        def multiply(q: Element, i: Int): Element = {
          tracer.out().printfIndentln("i = %d, q = %s", i: Integer, q)
          if (i == m.bitLength) q
          else {
            val nextQ = 
              if (m.testBit(i)) q add multiplies(i)._2
              else q
            multiply(nextQ, i + 1)
          }
        }
        
        multiply(new NeutralElement, 0)
      }
    }
    
    def multiply(m: BigInt): Element = multiply(m, this.fixedPoint)

    override def getCurrentTracer(): AbstractTracer = {
      try {
        TracerFactory.getInstance().getTracer("TestTracer")
      }
      catch {
        case ex: TracerFactory.Exception => TracerFactory.getInstance().getDefaultTracer
      }
    }
  }
  
  class MontgomeryLadder extends PointMultiplication with Tracing {
    def multiply(multiplier: BigInt, point: AffinePoint): Element = {
      val tracer = getCurrentTracer()
      withTracer("Element", this, "multiply(m: BigInt, point: AffinePoint)") {
        
        @tailrec
        def multiply(s: Element, t: Element, i: Int): Element = {
          tracer.out().printfIndentln("------------------")
          if (i >= 0) tracer.out().printfIndentln("testBit(%d) = %b", i: Integer, multiplier.testBit(i): java.lang.Boolean)
          tracer.out().printfIndentln("s = %s", s)
          tracer.out().printfIndentln("t = %s", t)
          
          if (i < 0) 
            s
          else {
            val (next_s, next_t): (Element, Element) =
              if (multiplier.testBit(i)) 
                (s add t, t add t)
              else 
                (s add s, s add t)
              multiply(next_s, next_t, i - 1)
          }
        }
        
        multiply(new NeutralElement, point, multiplier.bitLength - 1)
      }
    }
  }
}
