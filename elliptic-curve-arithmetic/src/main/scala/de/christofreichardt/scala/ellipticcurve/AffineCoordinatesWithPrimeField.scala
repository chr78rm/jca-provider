package de.christofreichardt.scala.ellipticcurve

import de.christofreichardt.scala.diagnosis.Tracing
import de.christofreichardt.diagnosis.AbstractTracer
import de.christofreichardt.diagnosis.TracerFactory
import scala.annotation.tailrec
import java.math.BigInteger

package affine {
  abstract class AffineCoordinatesWithPrimeField extends GroupLaw {
    lazy val multiplicationMethod: UnknownPointMultiplication = detectMultiplicationMethod()
    def detectMultiplicationMethod(): UnknownPointMultiplication = {
      val provider = java.security.Security.getProvider(de.christofreichardt.crypto.Provider.NAME)
      val multiplicationKey = "de.christofreichardt.scala.ellipticcurve.multiplicationMethod"
      val method: UnknownPointMultiplication =
        if (provider != null) {
          val multiplicationValue = provider.getProperty(multiplicationKey)
          multiplicationValue match {
            case "MontgomeryLadder"   => new MontgomeryLadder
            case "DoubleAndAddAlways" => new DoubleAndAddAlways
            case "BinaryMethod"       => new BinaryMethod
            case _                    => new MontgomeryLadder
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
      def fixedMultiply(scalar: BigInteger): Element = this.fixedPointMultiplication.multiply(scalar, this)
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

      override def multiply(multiplier: BigInt, point: AbstractPoint): Element = {
        require(point == this.fixedPoint, "Multiplication is fixed.")
        val tracer = getCurrentTracer

        @tailrec
        def multiply(q: Element, i: Int): Element = {
          tracer.out().printfIndentln("i = %d, q = %s", i: Integer, q)
          if (i == multiplier.bitLength) q
          else {
            val sum = q add multiplies(i)._2
            val nextQ =
              if (multiplier.testBit(i)) sum
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
          TracerFactory.getInstance().getDefaultTracer
        }
        catch {
          case ex: TracerFactory.Exception => TracerFactory.getInstance().getDefaultTracer
        }
      }
    }
  }  
}
