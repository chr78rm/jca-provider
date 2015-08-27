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
      val bInv = this.b.modInverse(this.p)
      def evaluateCurveEquation(x: BigInt): BigInt = (x.modPow(3, this.p) + (this.a*x.modPow(2, this.p)).mod(this.p) + x).mod(this.p)
      
      override def randomPoint: Point = super.randomPoint
      def randomPoint(randomGenerator: RandomGenerator): Point = {
        withTracer("Element", this, "add(point: AffinePoint)") {
          val x = randomGenerator.bigIntStream(this.p.bitLength * 2, p).find(x => {
            val test = (evaluateCurveEquation(x) * bInv).mod(this.p)
            test == BigInt(0) || this.legendreSymbol.isQuadraticResidue(test)
          }).get
          val value = (evaluateCurveEquation(x) * bInv).mod(this.p)
          if (value != BigInt(0)) {
            val (y1, y2) = this.solver.solve(evaluateCurveEquation(x))
            if (randomGenerator.bitStream.head) new Point(x, y1, this)
            else new Point(x, y2, this)
          }
          else
            new Point(x, 0, this)
        }
      }
      
      def isValidPoint(point: ThePoint): Boolean = {
        withTracer("Boolean", this, "isValidPoint(point: ThePoint)") {
          val tracer = getCurrentTracer()
          tracer.out().printfIndentln("point = %s", point)
          
          val value = (evaluateCurveEquation(point.x) * bInv).mod(this.p)
          if (this.legendreSymbol.compute(value) != -1) {
            val (y1, y2) = this.solver.solve(value)
            point.y == y1  ||  point.y == y2
          }
          else
            false
        }
      }
      
      def toShortWeierstrassCurve: ShortWeierstrass.Curve = {
        withTracer("ShortWeierstrass.Curve", this, "toShortWeierstrassCurve()") {
          val A = this.a
          val B = this.b
          val numeratorA = (3 - A.modPow(2, this.p)).mod(this.p)
          val denominatorA = (3*B.modPow(2, this.p)).mod(this.p)
          val numeratorB = (2*A.modPow(3, this.p) - 9*A).mod(this.p)
          val denominatorB = (27*B.modPow(3, this.p)).mod(this.p)
          val (a,b) = ((numeratorA*denominatorA.modInverse(this.p)).mod(this.p), (numeratorB*denominatorB.modInverse(this.p)).mod(this.p))
          ShortWeierstrass.makeCurve(ShortWeierstrass.OddCharCoefficients(a, b), ShortWeierstrass.PrimeField(this.p))
        }
      }
            
      override def toString() = {
        "Montgomery[a=" + this.a + ", b=" + this.b + ", p=" + this.p + "]"
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
    
    class Point(x: BigInt, y: BigInt, curve: Curve) extends AffinePoint(x,y, curve) with Equals with Tracing {
      override def negate = new Point(this.x, (-this.y).mod(this.curve.p), this.curve)
      
      override def add(point: Point): Element = {
        val tracer = getCurrentTracer()
        withTracer("Element", this, "add(point: AffinePoint)") {
          tracer.out().printfIndentln("this = %s", this)
          tracer.out().printfIndentln("point = %s", point)
          tracer.out().printfIndentln("point.negate = %s", point.negate)

          if (this != point.negate) {
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
      
      def toShortWeierstrassPoint: ShortWeierstrass.Point = {
        withTracer("ShortWeierstrass.Point", this, "toShortWeierstrassPoint()") {
          val A = this.curve.a
          val B = this.curve.b
          val transformedX = ((this.x*B.modInverse(this.curve.p)).mod(this.curve.p) + (A*(3*B).modInverse(this.curve.p))).mod(this.curve.p)
          val transformedY = (this.y*B.modInverse(this.curve.p)).mod(this.curve.p)
          ShortWeierstrass.makePoint(ShortWeierstrass.AffineCoordinates(transformedX, transformedY), this.curve.toShortWeierstrassCurve)
        }
      }
      
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

    def makeCurve(coefficients: TheCoefficients, finiteField: TheFiniteField): Curve = {
      require(finiteField.p.isProbablePrime(Constants.CERTAINTY))
      require(coefficients.a.mod(finiteField.p) != BigInt(2)  &&  coefficients.a.mod(finiteField.p) != BigInt(-2).mod(finiteField.p)  &&  coefficients.b != BigInt(0))
      new Curve(coefficients.a, coefficients.b, finiteField.p)
    }
    
    def makePoint(coordinates: TheCoordinates, curve: TheCurve): Point = new Point(coordinates.x.mod(curve.p), coordinates.y.mod(curve.p), curve)

    implicit def elemToAffinePoint(elem: Element): Point = {
      elem match {
        case el: NeutralElement => throw new NeutralElementException("Neutral element has been trapped.")
        case ap: Point    => ap
      }
    }
  }
}

package projective {
  object Montgomery extends GroupLaw with Tracing {
    type TheCoefficients = OddCharCoefficients
    type TheFiniteField = PrimeField
    type TheCurve = Curve
    type ThePoint = Point
    type TheCoordinates = ProjectiveCoordinates
    
    case class OddCharCoefficients(a: BigInt, b: BigInt) extends Coefficients
    case class ProjectiveCoordinates(x: BigInt, y: BigInt, z: BigInt) extends Coordinates
    
    case class PrimeField(p: BigInt) extends FiniteField
    def makePrimeField(p: BigInt): PrimeField = new PrimeField(p)
    
    class Curve(val affineCurve: affine.Montgomery.Curve) extends AbstractCurve {
      val c = (this.affineCurve.a + BigInt(2))*BigInt(4).modInverse(this.affineCurve.p)
      def randomPoint: Point = {
        val affinePoint = affineCurve.randomPoint
        new Point(affinePoint.x, affinePoint.y, BigInt(1), this)
      }
    }
    
    class Point(val x: BigInt, val y: BigInt, val z: BigInt, curve: Curve) extends AbstractPoint {
      def negate: Point = throw new UnsupportedOperationException
      def add(element: Point): Element = throw new UnsupportedOperationException("Only differential addition defined.")
      
      def multiply(scalar: BigInt): Element = {
        val tracer = getCurrentTracer()
        
        val p = this.curve.affineCurve.p
        def multiply(n: BigInt): Tuple2[Point, Point] = {
          tracer.out().printfIndentln("n = %s", n)

          def double(point: Point): Point = {
            withTracer("Point", this, "double(point: Point)") {
              tracer.out().printfIndentln("point = %s", point)
              
              val x = point.x
              val z = point.z
              val d = (((x + z) * (x + z)).mod(p) - ((x - z) * (x - z)).mod(p)).mod(p)
              val x_result = (((x + z) * (x + z)).mod(p) * ((x - z) * (x - z)).mod(p)).mod(p)
              val z_result = (d * (((x - z) * (x - z)).mod(p) + (this.curve.c * d).mod(p))).mod(p)
              new Point(x_result, null, z_result, this.curve)
            }
          }

          def add(point1: Point, point2: Point): Point = {
            withTracer("Point", this, "add(point1: Point, point2: Point)") {
              tracer.out().printfIndentln("point1 = %s", point1)
              tracer.out().printfIndentln("point2 = %s", point2)
              
              val xn = point1.x
              val xm = point2.x
              val zn = point1.z
              val zm = point2.z
              val e = ((xm - zm) * (xn + zn)).mod(p)
              val f = ((xm + zm) * (xn - zn)).mod(p)
              val x_result = this.z * (e + f).modPow(2, p)
              val z_result = this.x * (e - f).modPow(2, p)
              new Point(x_result, null, z_result, this.curve)
            }
          }
          
          if (n == 2) {
            val point1 = double(this)
            val point2 = add(point1, this)
            (point1, point2)
          }
          else if (n == 3) {
            val twofold = double(this)
            val point1 = add(twofold, this)
            val point2 = double(twofold)
            (point1, point2)
          }
          else {
            val next_n = n / 2
            val pointPair = multiply(next_n)
            
            if (n % 2 == 0) {
              val point1 = double(pointPair._1)
              val point2 = add(pointPair._1, pointPair._2)
              (point1, point2)
            }
            else {
              val point1 = add(pointPair._1, pointPair._2)
              val point2 = double(pointPair._2)
              (point1, point2)
            }
          }
        }
        
        withTracer("Element", this, "multiply(scalar: BigInt)") {
          tracer.out().printfIndentln("scalar = %s", scalar)
          tracer.out().printfIndentln("this = %s", this)
          
          val pointPair: Tuple2[Point, Point] = multiply(scalar)
            
          tracer.out().printfIndentln("pointPair = %s", pointPair)
            
          if (pointPair._1.z != 0) {
            val scaled_x = (pointPair._1.x*pointPair._1.z.modInverse(p)).mod(p)
            val scaled_x1 = pointPair._2.x*pointPair._2.z.modInverse(p)
            val affine_x = this.x*this.z.modInverse(p)
            val denominator = (2*this.curve.affineCurve.b*this.y).modInverse(p)
            val s = (affine_x*scaled_x + 1).mod(p)
            val t = (affine_x + scaled_x + 2*this.curve.affineCurve.a).mod(p)
            val u = ((affine_x - scaled_x).modPow(2, p)*scaled_x1).mod(p)
            val numerator = ((s*t).mod(p) - (2*this.curve.affineCurve.a).mod(p) - u).mod(p)
            val scaled_y = (numerator*denominator).mod(p)
            new Point(scaled_x, scaled_y, 1, this.curve)
          }
          else
            new NeutralElement
        }
      }
      
      override def toString() = {
        "ProjectivePoint[" + this.x + ", " + this.y + ", " + this.z + "]"
      }
    }
    
    def makeCurve(coefficients: TheCoefficients, finiteField: TheFiniteField): Curve = {
      val affineCurve = affine.Montgomery.makeCurve(affine.Montgomery.OddCharCoefficients(coefficients.a, coefficients.b), affine.Montgomery.PrimeField(finiteField.p))
      new Curve(affineCurve)
    }
    
    def makePoint(coordinates: TheCoordinates, curve: TheCurve): Point = new Point(coordinates.x, coordinates.y, coordinates.z, curve)

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
