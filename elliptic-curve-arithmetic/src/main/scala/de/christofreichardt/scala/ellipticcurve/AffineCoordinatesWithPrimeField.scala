package de.christofreichardt.scala.ellipticcurve

import de.christofreichardt.scala.diagnosis.Tracing
import de.christofreichardt.diagnosis.AbstractTracer
import de.christofreichardt.diagnosis.TracerFactory
import scala.annotation.tailrec

package affine {
  abstract class AffineCoordinatesWithPrimeField extends GroupLaw {
    lazy val multiplicationMethod: UnknownPointMultiplication = detectMultiplicationMethod()
    def detectMultiplicationMethod(): UnknownPointMultiplication = {
      val provider = java.security.Security.getProvider(de.christofreichardt.crypto.Provider.NAME)
      val multiplicationKey = "de.christofreichardt.scala.ellipticcurve.affine.multiplicationMethod"
      val method: UnknownPointMultiplication =
        if (provider != null) {
          val multiplicationValue = provider.getProperty(multiplicationKey)
          multiplicationValue match {
            case "MontgomeryLadder"  => new MontgomeryLadder
            case "MontgomeryLadder2" => new MontgomeryLadder2
            case "BinaryMethod"      => new BinaryMethod
            case _                   => new MontgomeryLadder
          }
        }
        else {
          new MontgomeryLadder
        }
          
      method
    }
    
    type TheFiniteField = PrimeField
    type ThePoint <: AffinePoint
    type TheCurve <: AffineCurve
    type TheCoordinates = AffineCoordinates
    
    case class AffineCoordinates(x: BigInt, y: BigInt) extends Coordinates
    def makeAffineCoordinates(x: BigInt, y: BigInt): AffineCoordinates = new AffineCoordinates(x, y)
    
    case class PrimeField(p: BigInt) extends FiniteField
    def makePrimeField(p: BigInt): PrimeField = new PrimeField(p)
    
    abstract class AffinePoint(val x: BigInt, val y: BigInt, val curve: TheCurve) extends AbstractPoint {
      lazy val fixedPointMultiplication: FixedPointMultiplication = new FixedPointBinaryMethod(this)
      def fixedMultiply(scalar: BigInt): Element = this.fixedPointMultiplication.multiply(scalar, this)
      override def toString() = {
        "AffinePoint[" + this.x + ", " + this.y + "]"
      }
    }
    abstract class AffineCurve(val p: BigInt) extends AbstractCurve {
      require(p.isProbablePrime(Constants.CERTAINTY), p + " isn't prime.")
      val legendreSymbol: LegendreSymbol = new EulersCriterion(this.p)
      val solver = new QuadraticResidue(this.p)
      def evaluateCurveEquation(x: BigInt): BigInt
      def randomPoint: ThePoint = {
        val randomGenerator = new RandomGenerator
        randomPoint(randomGenerator)
      }
      def randomPoint(randomGenerator: RandomGenerator): ThePoint
      def isValidPoint(point: ThePoint): Boolean
    }

    trait PointMultiplication extends Tracing {
      def multiply(m: BigInt, point: AffinePoint): Element
      
      override def getCurrentTracer(): AbstractTracer = {
        try {
          TracerFactory.getInstance().getDefaultTracer
        }
        catch {
          case ex: TracerFactory.Exception => TracerFactory.getInstance().getDefaultTracer
        }
      }
    }
    
    trait UnknownPointMultiplication extends PointMultiplication

    class BinaryMethod extends UnknownPointMultiplication {
      def multiply(multiplier: BigInt, point: AffinePoint): Element = {
        val tracer = getCurrentTracer()
        
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
              if (multiplier.testBit(i - 1)) point add double
              else double
            multiply(sum, i - 1)
          }
        }
        
        withTracer("Element", this, "multiply(m: BigInt, point: AffinePoint)") {
          tracer.out().printfIndentln("multiplier(%d) = %s", multiplier.bitLength: Integer, multiplier)
          tracer.out().printfIndentln("point = %s", point)

          if (multiplier == BigInt(0)) new NeutralElement
          else multiply(new NeutralElement, multiplier.bitLength)
        }
      }
    }
    
    trait FixedPointMultiplication extends PointMultiplication {
      val fixedPoint: AffinePoint
    }

    class FixedPointBinaryMethod(val fixedPoint: AffinePoint)
        extends FixedPointMultiplication {

      def twoPowerPointStream: Stream[(Int, Element)] = {
        def pointStream(exp: Int, power: BigInt, element: Element): Stream[(Int, Element)] = {
          if (exp == 0) Stream.cons((exp, this.fixedPoint), pointStream(1, BigInt(1), this.fixedPoint))
          else if (exp == 1) {
            val nextPoint = this.fixedPoint add this.fixedPoint
            Stream.cons((exp, nextPoint), pointStream(2, BigInt(2), nextPoint))
          }
          else {
            val nextPower = power * BigInt(2)
            if (nextPower < this.fixedPoint.curve.p * 2) {
              val nextPoint = element add element
              Stream.cons((exp, nextPoint), pointStream(exp + 1, nextPower, nextPoint))
            }
            else
              Stream.empty[(Int, Element)]
          }
        }
        pointStream(0, BigInt(1), this.fixedPoint)
      }

      lazy val multiplies = twoPowerPointStream.toIndexedSeq

      def multiply(multiplier: BigInt, point: AffinePoint): Element = {
        require(point == this.fixedPoint, "Multiplication is fixed.")
        val tracer = getCurrentTracer

        @tailrec
        def multiply(q: Element, i: Int): Element = {
          tracer.out().printfIndentln("i = %d, q = %s", i: Integer, q)
          if (i == multiplier.bitLength) q
          else {
            val nextQ =
              if (multiplier.testBit(i)) q add multiplies(i)._2
              else q
            multiply(nextQ, i + 1)
          }
        }

        withTracer("Element", this, "multiply(m: BigInt, point: AffinePoint)") {
          tracer.out().printfIndentln("multiplier(%d) = %s", multiplier.bitLength: Integer, multiplier)
          tracer.out().printfIndentln("point = %s", point)

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

    class MontgomeryLadder extends UnknownPointMultiplication {
      def multiply(multiplier: BigInt, point: AffinePoint): Element = {
        val tracer = getCurrentTracer()
        
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
        
        withTracer("Element", this, "multiply(m: BigInt, point: AffinePoint)") {
          tracer.out().printfIndentln("multiplier(%d) = %s", multiplier.bitLength: Integer, multiplier)
          tracer.out().printfIndentln("point = %s", point)
          
          multiply(new NeutralElement, point, multiplier.bitLength - 1)
        }
      }
    }

    class MontgomeryLadder2 extends UnknownPointMultiplication {
      def multiply(multiplier: BigInt, point: AffinePoint): Element = {
        val tracer = getCurrentTracer()
        
        @tailrec
        def multiply(element: Element, i: Int): Element = {
          tracer.out().printfIndentln("------------------")
          if (i >= 0) tracer.out().printfIndentln("testBit(%d) = %b", i: Integer, multiplier.testBit(i): java.lang.Boolean)
          tracer.out().printfIndentln("element = %s", element)

          if (i < 0)
            element
          else {
            val next: scala.collection.mutable.Map[Boolean, Element] = scala.collection.mutable.HashMap.empty[Boolean, Element]
            next += (false -> element.add(element))
            next += (true -> point.add(next(false)))
            multiply(next(multiplier.testBit(i)), i - 1)
          }
        }
        
        withTracer("Element", this, "multiply(m: BigInt, point: AffinePoint)") {
          tracer.out().printfIndentln("multiplier(%d) = %s", multiplier.bitLength: Integer, multiplier)
          tracer.out().printfIndentln("point = %s", point)
          
          multiply(new NeutralElement, multiplier.bitLength - 1)
        }
      }
    }
  }  
}
