package de.christofreichardt.scala.ellipticcurve

import de.christofreichardt.scala.diagnosis.Tracing
import de.christofreichardt.diagnosis.AbstractTracer
import de.christofreichardt.diagnosis.TracerFactory

package affine {
  object Montgomery extends AffineCoordinatesWithPrimeField {
    type TheCurve = Curve
    type TheCoefficients = OddCharCoefficients
    type ThePoint = Point

    case class OddCharCoefficients(a: BigInt, b: BigInt) extends Coefficients
    
    class Curve(val a: BigInt, val b: BigInt, p: BigInt) extends AffineCurve(p) with Tracing {
      def evaluateCurveEquation(x: BigInt): BigInt = (x.modPow(3, this.p) + (this.a*x.modPow(2, this.p)).mod(this.p) + x).mod(this.p)
      
      override def randomPoint: Point = super.randomPoint
      def randomPoint(randomGenerator: RandomGenerator): Point = {
        withTracer("Element", this, "add(point: AffinePoint)") {
          val x = randomGenerator.bigIntStream(this.p.bitLength * 2, p).find(x => {
            val test = (evaluateCurveEquation(x) * this.b.modInverse(this.p)).mod(this.p)
            test == BigInt(0) || this.legendreSymbol.isQuadraticResidue(test)
          }).get
          val value = (evaluateCurveEquation(x) * this.b.modInverse(this.p)).mod(this.p)
          if (value != BigInt(0)) {
            val (y1, y2) = this.solver.solve(evaluateCurveEquation(x))
            if (randomGenerator.bitStream.head) new Point(x, y1, this)
            else new Point(x, y2, this)
          }
          else
            new Point(x, 0, this)
        }
      }
      
      def isValidPoint(point: ThePoint): Boolean = false
            
      override def toString() = {
        "Montgomery[a=" + this.a + ", b=" + this.b + ", p=" + this.p + "]"
      }
    }
    
    class Point(x: BigInt, y: BigInt, curve: Curve) extends AffinePoint(x,y, curve) with Equals with Tracing {
      override def negate = new Point(this.x, (-this.y).mod(this.curve.p), this.curve)
      
      override def add(point: Point): Element = {
        val tracer = getCurrentTracer()
        withTracer("Element", this, "add(point: AffinePoint)") {
          tracer.out().printfIndentln("this = %s", this)
          tracer.out().printfIndentln("point = %s", point)
          tracer.out().printfIndentln("point.negate = %s", point.negate)

          if (this != point.negate) {
//            val lambda =
//              if (this != point)
//                ((point.y - this.y) * (point.x - this.x).modInverse(this.curve.p)).mod(this.curve.p)
//              else
//                (((3 * this.x.modPow(2, this.curve.p)) + (2 * this.curve.a + this.x) + 1).mod(this.curve.p) * (2 * this.curve.b * this.y).modInverse(this.curve.p)).mod(this.curve.p)
//            val x = (((this.curve.b * lambda.modPow(2, this.curve.p))).mod(this.curve.p) - this.curve.a - this.x - point.x).mod(this.curve.p)
//            val y = ((lambda * (this.x - x)).mod(this.curve.p) - this.y).mod(this.curve.p)
//            new Point(x, y, this.curve)
            if (this != point) {
              val xa = (this.curve.b * (point.y - this.y).modPow(2, this.curve.p)).mod(this.curve.p)
              val xb = (point.x - this.x).modPow(2, this.curve.p)
              val x = (xa * xb.modInverse(this.curve.p) - this.curve.a - this.x - point.x).mod(this.curve.p)
              val ya = ((((2*this.x + point.x + this.curve.a) * (point.y - this.y)).mod(this.curve.p)) * (point.x - this.x).modInverse(this.curve.p)).mod(this.curve.p)
              val yb = ((((this.curve.b) * ((point.y - this.y).modPow(3, this.curve.p))).mod(this.curve.p)) * (((point.x - this.x).modPow(3, this.curve.p))).modInverse(this.curve.p)).mod(this.curve.p)
              val y = (ya - yb - this.y).mod(this.curve.p)
              new Point(x, y, this.curve)
            }
            else {
              val xa = this.curve.b * ((3 * this.x.modPow(2, this.curve.p)) + (2 * this.curve.a * this.x).mod(this.curve.p) + 1).modPow(2, this.curve.p)
              val xb = (2 * this.curve.b * this.y).modPow(2, this.curve.p).modInverse(this.curve.p)
              val x = ((xa * xb).mod(this.curve.p) - this.curve.a - this.x - this.x).mod(this.curve.p)
              val ya = (((2 * this.x + this.x + this.curve.a).mod(this.curve.p)) * (((3 * this.x.modPow(2, this.curve.p)) + (2 * this.curve.a * this.x).mod(this.curve.p) + 1).mod(this.curve.p))).mod(this.curve.p)
              val yb = (2 * this.curve.b * this.y).modInverse(this.curve.p)
              val yc = ((this.curve.b * ((3 * this.x.modPow(2, this.curve.p)) + (2 * this.curve.a * this.x).mod(this.curve.p) + 1).modPow(3, this.curve.p))).mod(this.curve.p)
              val yd = ((2 * this.curve.b * this.y).modPow(3, this.curve.p)).modInverse(this.curve.p)
              val y = ((ya * yb).mod(this.curve.p) - (yc * yd).mod(this.curve.p) - this.y).mod(this.curve.p)
              new Point(x, y, this.curve)
            }
          }
          else
            new NeutralElement
        }
      }
      
      override def multiply(scalar: BigInt): Element = Montgomery.multiplicationMethod.multiply(scalar, this)
      
      def canEqual(other: Any) = {
        other.isInstanceOf[Point]
      }

      override def equals(other: Any) = {
        other match {
          case that: Point => that.canEqual(Point.this) && x == that.x && y == that.y
          case _                 => false
        }
      }

      override def hashCode() = {
        val prime = 41
        prime * (prime + x.hashCode) + y.hashCode
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
    
    def makeCurve(coefficients: TheCoefficients, finiteField: TheFiniteField): Curve = new Curve(coefficients.a, coefficients.b, finiteField.p)
    def makePoint(coordinates: TheCoordinates, curve: TheCurve): Point = new Point(coordinates.x.mod(curve.p), coordinates.y.mod(curve.p), curve)

    implicit def elemToAffinePoint(elem: Element): Point = {
      elem match {
        case el: NeutralElement => throw new NeutralElementException("Neutral element has been trapped.")
        case ap: Point    => ap
      }
    }
  }
}
