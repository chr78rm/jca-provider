package de.christofreichardt.scala.ellipticcurve

import de.christofreichardt.scala.diagnosis.Tracing
import de.christofreichardt.diagnosis.AbstractTracer
import de.christofreichardt.diagnosis.TracerFactory
import de.christofreichardt.scala.ellipticcurve.affine.ShortWeierstrass

package projective {
  object JacobianShortWeierstrass extends GroupLaw with Tracing {
    type TheCoefficients = OddCharCoefficients
    type TheFiniteField = PrimeField
    type TheCurve = Curve
    type ThePoint = Point
    type TheCoordinates = ProjectiveCoordinates
    
    case class OddCharCoefficients(a: BigInt, b: BigInt) extends Coefficients
    case class ProjectiveCoordinates(x: BigInt, y: BigInt, z: BigInt) extends Coordinates
    
    case class PrimeField(p: BigInt) extends FiniteField
    def makePrimeField(p: BigInt): PrimeField = new PrimeField(p)
    
    class Curve(val a: BigInt, val b: BigInt, val p: BigInt) extends AbstractCurve {
      def randomPoint: Point = {
        val affineCurve = new ShortWeierstrass.Curve(a, b, p)
        val affinePoint = affineCurve.randomPoint
        new Point(affinePoint.x, affinePoint.y, BigInt(1), this)
      }
    }
    
    class Point(val x: BigInt, val y: BigInt, val z: BigInt, curve: Curve) extends AbstractPoint with Equals {
      def negate: Point = new Point(this.x, (-this.y).mod(this.curve.p), this.z, this.curve)

      def add(point: Point): Element = {
        val tracer = getCurrentTracer()
        withTracer("Element", this, "add(point: Point)") {
          tracer.out().printfIndentln("this = %s", this)
          tracer.out().printfIndentln("point = %s", point)
          tracer.out().printfIndentln("point.negate = %s", point.negate)
          
          if (!this.isCongruentTo(point.negate)) {
            val sum =
              if (this == point) {
                tracer.out().printfIndentln("Case P == Q")
                
                val a = (this.y * this.y).mod(this.curve.p)
                val b = (BigInt(4)*this.x*a).mod(this.curve.p)
                val c = (BigInt(8)*a*a).mod(this.curve.p)
                val d = ((BigInt(3)*this.x*this.x).mod(this.curve.p) + this.curve.a*this.z.modPow(4, this.curve.p)).mod(this.curve.p)
                val x3 = (d*d - BigInt(2)*b).mod(this.curve.p)
                val y3 = (d*(b - x3) - c).mod(this.curve.p)
                val z3 = (BigInt(2)*this.y*this.z).mod(this.curve.p)
                new Point(x3, y3, z3, this.curve)
              }
              else {
                tracer.out().printfIndentln("Case P != Q")
                
                val a = (this.x*point.z*point.z).mod(this.curve.p)
                val b = (point.x*this.z*this.z).mod(this.curve.p)
                val c = (this.y*point.z.modPow(3, this.curve.p)).mod(this.curve.p)
                val d = (point.y*this.z.modPow(3, this.curve.p)).mod(this.curve.p)
                val e = (b - a).mod(this.curve.p)
                val f = (d - c).mod(this.curve.p)
                val x3 = ((f*f).mod(this.curve.p) - e.modPow(3, this.curve.p) - (BigInt(2)*a*e*e).mod(this.curve.p)).mod(this.curve.p)
                val y3 = ((((a*e*e).mod(this.curve.p) - x3).mod(this.curve.p)*f).mod(this.curve.p) - (c*e.modPow(3, this.curve.p)).mod(this.curve.p)).mod(this.curve.p)
                val z3 = (this.z*point.z*e).mod(this.curve.p)
                new Point(x3, y3, z3, this.curve)
              }
            sum
          }
          else
            new NeutralElement
        }
      }
      
      def multiply(scalar: BigInt): Element = {
        val binaryMethod = new BinaryMethod
        binaryMethod.multiply(scalar, this)
      }

      def canEqual(other: Any) = {
        other.isInstanceOf[Point]
      }

      override def equals(other: Any) = {
        other match {
          case that: Point => that.canEqual(Point.this) && this.x == that.x && this.y == that.y && this.z == that.z
          case _ => false
        }
      }

      override def hashCode() = {
        val prime = 41
        prime * (prime * (prime + x.hashCode) + y.hashCode) + z.hashCode()
      }
      
      def isCongruentTo(other: Element): Boolean = {
        other match {
          case that: Point => ((this.x * that.z * that.z).mod(this.curve.p) == (that.x * this.z * this.z).mod(this.curve.p)) &&
          ((this.y * that.z.modPow(3, this.curve.p)).mod(this.curve.p) == (that.y * this.z.modPow(3, this.curve.p)).mod(this.curve.p))
          case _ => false
        }
        
      }
      
      override def toString() = {
        "ProjectivePoint[" + this.x + ", " + this.y + ", " + this.z + "]"
      }
      
      def toAffinePoint: ShortWeierstrass.Point = {
        val affineCurve = ShortWeierstrass.makeCurve(ShortWeierstrass.OddCharCoefficients(this.curve.a, this.curve.b), ShortWeierstrass.PrimeField(this.curve.p))
        val lambda = this.z.modInverse(this.curve.p)
        val x = ((lambda*lambda)*this.x).mod(this.curve.p)
        val y = (lambda*lambda*lambda*this.y).mod(this.curve.p)
        new ShortWeierstrass.Point(x, y, affineCurve)
      }
    }
    
    def makeCurve(coefficients: TheCoefficients, finiteField: TheFiniteField): Curve = new Curve(coefficients.a, coefficients.b, finiteField.p)
    def makePoint(coordinates: TheCoordinates, curve: TheCurve): Point = new Point(coordinates.x, coordinates.y, coordinates.z, curve)

    implicit def elemToAffinePoint(elem: Element): ShortWeierstrass.Point = {
      elem match {
        case el: NeutralElement => throw new NeutralElementException("Neutral element has been trapped.")
        case ap: Point    => ap.toAffinePoint
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
}