package de.christofreichardt.scala.ellipticcurve

import de.christofreichardt.scala.diagnosis.Tracing
import de.christofreichardt.diagnosis.AbstractTracer
import de.christofreichardt.diagnosis.TracerFactory

package affine {
  object Montgomery extends AffineCoordinatesWithPrimeField {
    type TheCurve = Curve
    type TheCoefficients = OddCharCoefficients

    case class OddCharCoefficients(a: BigInt, b: BigInt) extends Coefficients
    
    class Curve(val a: BigInt, val b: BigInt, p: BigInt) extends AffineCurve(p) with Tracing {
      def evaluateCurveEquation(x: BigInt): BigInt = (x.modPow(3, this.p) + (this.a*x.modPow(2, this.p)).mod(this.p) + x).mod(this.p)
      
      override def randomPoint: ThePoint = super.randomPoint
      def randomPoint(randomGenerator: RandomGenerator): ThePoint = {
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
      
    }
    
    class Point(x: BigInt, y: BigInt, curve: Curve) extends AffinePoint(x,y, curve) {
      override def negate = new Point(this.x, (-this.y).mod(this.curve.p), this.curve)
      override def add(point: ThePoint): Element = null
      override def multiply(scalar: BigInt): Element = null
    }
    
    def makeCurve(coefficients: TheCoefficients, finiteField: TheFiniteField): TheCurve = new Curve(coefficients.a, coefficients.b, finiteField.p)
    def makePoint(coordinates: TheCoordinates, curve: TheCurve): Point = new Point(coordinates.x.mod(curve.p), coordinates.y.mod(curve.p), curve)
  }
}
