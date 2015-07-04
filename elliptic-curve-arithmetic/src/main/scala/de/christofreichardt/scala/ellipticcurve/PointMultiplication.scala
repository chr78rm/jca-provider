package de.christofreichardt.scala.ellipticcurve

package affine {

  import de.christofreichardt.diagnosis.AbstractTracer
  import de.christofreichardt.diagnosis.TracerFactory
  import de.christofreichardt.scala.diagnosis.Tracing
  import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesOddCharacteristic.elemToAffinePoint

  import scala.BigInt
  import scala.Stream
  import scala.annotation.tailrec

  import AffineCoordinatesOddCharacteristic.NeutralElement

  class FixedPointBinaryMethod(val fixedPoint: AffineCoordinatesOddCharacteristic.AffinePoint)
      extends AffineCoordinatesOddCharacteristic.PointMultiplication with Tracing {

    type AffinePoint = AffineCoordinatesOddCharacteristic.AffinePoint
    type Element = AffineCoordinatesOddCharacteristic.Element
    
    def twoPowerPointStream: Stream[(Int, Element)] = {
      def pointStream(exp: Int, power: BigInt, element: Element): Stream[(Int, Element)] = {
        if (exp == 0) Stream.cons((exp, this.fixedPoint), pointStream(1, BigInt(1), this.fixedPoint))
        else if (exp == 1) {
          val nextPoint = this.fixedPoint add this.fixedPoint
          Stream.cons((exp, nextPoint), pointStream(2, BigInt(2), nextPoint))
        }
        else {
          val nextPower = power*BigInt(2)
          if (nextPower < this.fixedPoint.curve.p) {
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
}
