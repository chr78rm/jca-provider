package de.christofreichardt.scala.ellipticcurve

import scala.annotation.tailrec
import de.christofreichardt.scala.diagnosis.Tracing
import de.christofreichardt.diagnosis.AbstractTracer
import de.christofreichardt.diagnosis.TracerFactory
import java.io.File
import java.io.RandomAccessFile
import java.io.PrintStream
import scala.util.Random
import java.math.MathContext
import java.math.RoundingMode
import scala.language.implicitConversions

package affine {
  object ShortWeierstrass extends AffineCoordinatesWithPrimeField with Tracing {
    type TheCurve = Curve
    type TheCoefficients = OddCharCoefficients
    type ThePoint = Point

    case class OddCharCoefficients(a: BigInt, b: BigInt) extends Coefficients
    
    def isCurve(a: BigInt, b: BigInt, p: BigInt): Boolean = (-16 * (4 * a.pow(3) + 27 * b.pow(2))) != 0

    class Curve(val a: BigInt, val b: BigInt, p: BigInt) extends AffineCurve(p) {
      require(isCurve(a, b, p))

      override def randomPoint: Point = super.randomPoint
      def randomPoint(randomGenerator: RandomGenerator): Point = {
        val x = randomGenerator.bigIntStream(this.p.bitLength * 2, p).find(x => {
          val test = evaluateCurveEquation(x)
          test == BigInt(0)  ||  this.legendreSymbol.isQuadraticResidue(test)
        }).get
        val value = evaluateCurveEquation(x)
        if (value != BigInt(0)) {
          val (y1, y2) = this.solver.solve(evaluateCurveEquation(x))
          if (randomGenerator.bitStream.head) new Point(x, y1, this)
          else new Point(x, y2, this)
        }
        else
          new Point(x, 0, this)
      }

      def evaluateCurveEquation(x: BigInt): BigInt = (x.modPow(3, this.p) + (this.a * x).mod(this.p) + this.b).mod(this.p)
      def computeOrder(groupOrderCalculus: GroupOrderCalculus) = groupOrderCalculus.computeOrder(this)

      def draw(file: File): Unit = {
        val limit = 100
        if (this.p > BigInt(limit)) throw new UnsupportedOperationException("Modulus too big.")

        val width = (this.p + 1).toInt
        val line = " " * width
        val printStream = new PrintStream(file)
        try {
          for {
            i <- 0 until width
          } printStream.printf("%s\n", line)
        }
        finally {
          printStream.close()
        }

        val randomAccessFile = new RandomAccessFile(file, "rw")
        try {
          val size = randomAccessFile.length()

          def plot(x: Int, y: Int, s: String): Unit = {
            randomAccessFile.seek(size - (width + 1) * y + (x - (width + 1)))
            randomAccessFile.writeBytes(s)
          }

          (0 until width).foreach(i => {
            if (i % 5 == 0) {
              plot(0, i, "-")
              plot(i, 0, "|")
            }
            else {
              plot(0, i, "|")
              plot(i, 0, "-")
            }
          })

          val range = BigInt(0) until this.p
          range.foreach(x => {
            val test = evaluateCurveEquation(x)
            val value = this.legendreSymbol.compute(test)
            if (value == 1) {
              val (y1, y2) = this.solver.solve(evaluateCurveEquation(x))
              plot(x.toInt, y1.toInt, "*")
              plot(x.toInt, y2.toInt, "*")
            }
            else if (value == 0)
              plot(x.toInt, 0, "*")
          })
        }
        finally {
          randomAccessFile.close()
        }
      }

      def isValidPoint(point: Point): Boolean = {
        val yQuadrat = evaluateCurveEquation(point.x)
        if (this.legendreSymbol.compute(yQuadrat) != -1) {
          val (y1, y2) = this.solver.solve(yQuadrat)
          point.y == y1  ||  point.y == y2
        }
        else
          false
      }
      
      override def toString() = {
        "ShortWeierstrass[a=" + this.a + ", b=" + this.b + ", p(" + this.p.bitLength + ")=" + this.p + "]"
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
            val lambda =
              if (this != point) ((point.y - this.y) * (point.x - this.x).modInverse(this.curve.p)).mod(this.curve.p)
              else ((3 * this.x.pow(2) + this.curve.a).mod(this.curve.p) * (2 * this.y).modInverse(this.curve.p)).mod(this.curve.p)
            val x = (lambda.modPow(2, this.curve.p) - this.x - point.x).mod(this.curve.p)
            val y = ((this.x - x) * lambda - this.y).mod(this.curve.p)
            new Point(x, y, this.curve)
          }
          else
            new NeutralElement
        }
      }

      override def multiply(scalar: BigInt): Element = {
        ShortWeierstrass.multiplicationMethod.multiply(scalar, this)
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

    def makeCurve(coefficients: TheCoefficients, finiteField: TheFiniteField): Curve = new Curve(coefficients.a, coefficients.b, finiteField.p)
    def makePoint(coordinates: TheCoordinates, curve: Curve): Point = {
      val point = new Point(coordinates.x.mod(curve.p), coordinates.y.mod(curve.p), curve)
      require(curve.isValidPoint(point), "Invalid point.")
      point
    }

    implicit def elemToAffinePoint(elem: Element): Point = {
      elem match {
        case el: NeutralElement => throw new NeutralElementException("Neutral element has been trapped.")
        case ap: Point    => ap
      }
    }

    trait GroupOrderCalculus {
      val groupLaw = ShortWeierstrass
      
      def squareRoot(a: BigDecimal): BigDecimal = {
        withTracer("BigDecimal", this, "squareRoot(a: BigDecimal)") {
          val tracer = getCurrentTracer()
          tracer.out().printfIndentln("a = %s", a)
          val epsilon = BigDecimal(0.1)
          val x0 = BigDecimal(BigInt(a.toBigInt().bitLength/2, new Random) + BigInt(1))
          @tailrec
          def heron(x: BigDecimal): BigDecimal = {
            tracer.out().printfIndentln("x = %s", x)
            if ((a - x*x).abs < epsilon) x
            else heron((x + a/x)/BigDecimal(2))
          }
          heron(x0)
        }
      }
      
      def computeOrder(curve: Curve): BigInt
      def hasseTheorem(curve: Curve): (BigInt, BigInt, BigDecimal) = {
        val pSquared = squareRoot(BigDecimal(curve.p))
        val lowerLimit = curve.p + BigInt(1) - BigInt(2)*pSquared.round(new MathContext(1, RoundingMode.CEILING)).toBigInt()
        val upperLimit = curve.p + BigInt(1) + BigInt(2)*pSquared.round(new MathContext(1, RoundingMode.CEILING)).toBigInt()
        (lowerLimit, upperLimit, pSquared)
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

