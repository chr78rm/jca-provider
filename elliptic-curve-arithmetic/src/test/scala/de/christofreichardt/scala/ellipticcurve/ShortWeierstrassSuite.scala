package de.christofreichardt.scala.ellipticcurve

import scala.BigInt
import scala.math.BigInt.int2bigInt
import de.christofreichardt.scalatest.MyFunSuite
import scala.util.Random
import java.io.File
import java.io.RandomAccessFile
import java.io.PrintStream
import scala.collection.mutable.HashSet
import de.christofreichardt.diagnosis.LogLevel

package affine {
  import ShortWeierstrass.AffineCurve
  import ShortWeierstrass.AffinePoint
  import ShortWeierstrass.elemToAffinePoint
  
  class ShortWeierstrassSuite extends MyFunSuite {
    val groupLaw = ShortWeierstrass
    val curve1 = groupLaw.makeCurve(groupLaw.OddCharCoefficients(4, 20), groupLaw.PrimeField(29))
    val curve2 = groupLaw.makeCurve(groupLaw.OddCharCoefficients(71, 602), groupLaw.PrimeField(1009))
    val curve3 = groupLaw.makeCurve(groupLaw.OddCharCoefficients(146, 33), groupLaw.PrimeField(173))

    testWithTracing(this, "Point Addition (P + Q = R)") {
      val coordinates1 = groupLaw.AffineCoordinates(5, 22)
      val point1 = groupLaw.makePoint(coordinates1, curve1)
      val coordinates2 = groupLaw.AffineCoordinates(16, 27)
      val point2 = groupLaw.makePoint(coordinates2, curve1)
      val point3 = point1 add point2

      val tracer = getCurrentTracer()
      tracer.out().printfIndentln("point3 = %s", point3)

      assert(point3.x == BigInt(13) && point3.y == BigInt(6))
    }

    testWithTracing(this, "Point Addition (P + (-P) = 0)") {
      val coordinates1 = groupLaw.AffineCoordinates(5, 22)
      val point1 = groupLaw.makePoint(coordinates1, curve1)
      val coordinates2 = groupLaw.AffineCoordinates(5, -22)
      val point2 = groupLaw.makePoint(coordinates2, curve1)
      val point3 = point1 add point2

      val tracer = getCurrentTracer()
      tracer.out().printfIndentln("point3 = %s", point3)

      assert(point3.isNeutralElement)
    }

    testWithTracing(this, "Point Addition (P + 0 = P)") {
      val coordinates1 = groupLaw.AffineCoordinates(5, 22)
      val point1 = groupLaw.makePoint(coordinates1, curve1)
      val coordinates2 = groupLaw.AffineCoordinates(5, -22)
      val point2 = groupLaw.makeNeutralElement
      val point3 = point1 add point2
      val point4 = point2 add point1

      val tracer = getCurrentTracer()
      tracer.out().printfIndentln("point3 = %s", point3)

      assert(point3 == point1 && point4 == point1)
    }

    testWithTracing(this, "Point Multiplication m*P=Q (1)") {
      val tracer = getCurrentTracer()
      val coordinates = groupLaw.AffineCoordinates(1, 5)
      val point1 = groupLaw.makePoint(coordinates, this.curve1)
      val testVector = List(
        (1, groupLaw.AffineCoordinates(1, 5)),
        (2, groupLaw.AffineCoordinates(4, 19)),
        (3, groupLaw.AffineCoordinates(20, 3)),
        (4, groupLaw.AffineCoordinates(15, 27)),
        (5, groupLaw.AffineCoordinates(6, 12)),
        (6, groupLaw.AffineCoordinates(17, 19)),
        (7, groupLaw.AffineCoordinates(24, 22)),
        (8, groupLaw.AffineCoordinates(8, 10)),
        (9, groupLaw.AffineCoordinates(14, 23)),
        (10, groupLaw.AffineCoordinates(13, 23)),
        (11, groupLaw.AffineCoordinates(10, 25)),
        (12, groupLaw.AffineCoordinates(19, 13)),
        (13, groupLaw.AffineCoordinates(16, 27)))
      val testResult =
        testVector.forall(test => {
          val scalar = BigInt(test._1)
          val point2 = point1.multiply(scalar)

          tracer.out().printfIndentln("%s*%s = %s", scalar, point1, point2)

          point2 == groupLaw.makePoint(test._2, curve1)
        })
      assert(testResult)
    }

    testWithTracing(this, "Point Multiplication m*P=Q (2)") {
      val tracer = getCurrentTracer()

      val coordinates = groupLaw.AffineCoordinates(32, 737)
      val point1 = groupLaw.makePoint(coordinates, this.curve2)
      val scalar = BigInt(419)
      val point2 = point1.multiply(scalar)

      tracer.out().printfIndentln("%s*%s = %s", scalar, point1, point2)
      assert(point2.x == 592 && point2.y == 97)
    }

    testWithTracing(this, "Point Multiplication order(P)*P=0 (1)") {
      val tracer = getCurrentTracer()
      val coordinates = groupLaw.AffineCoordinates(1, 5)
      val point1 = groupLaw.makePoint(coordinates, this.curve1)
      val scalar = BigInt(37)
      try {
        intercept[groupLaw.NeutralElementException] {
          val element = point1.multiply(scalar)
          tracer.out().printfIndentln("%s*%s = %s", scalar, point1, element)
          val point2: ShortWeierstrass.AffinePoint = element
        }
      }
      catch {
        case ex: Exception => assert(false)
      }
    }

    testWithTracing(this, "Point Multiplication order(P)*P=0 (2)") {
      val tracer = getCurrentTracer()
      val coordinates = groupLaw.AffineCoordinates(1, 237)
      val point1 = groupLaw.makePoint(coordinates, this.curve2)
      val scalar = BigInt(530)
      try {
        intercept[groupLaw.NeutralElementException] {
          val element = point1.multiply(scalar)
          tracer.out().printfIndentln("%s*%s = %s", scalar, point1, element)
          val point2: ShortWeierstrass.AffinePoint = element
        }
      }
      catch {
        case ex: Exception => assert(false)
      }
    }

    testWithTracing(this, "Point Multiplication order(P)*P=0 (3)") {
      val tracer = getCurrentTracer()
      val coefficients = this.groupLaw.OddCharCoefficients(10, BigInt("1343632762150092499701637438970764818528075565078"))
      val primeField = this.groupLaw.PrimeField(BigInt(2).pow(160) + 7)
      val curve = this.groupLaw.makeCurve(coefficients, primeField)
      val point = curve.randomPoint
      val order = BigInt("1461501637330902918203683518218126812711137002561")
      val element = point multiply order
      assert(element.isNeutralElement, "Expected the NeutralElement.")
    }

    testWithTracing(this, "Random Point") {
      val tracer = getCurrentTracer()
      val coordinates = List(
        groupLaw.AffineCoordinates(0, 7),
        groupLaw.AffineCoordinates(0, 22),
        groupLaw.AffineCoordinates(1, 5),
        groupLaw.AffineCoordinates(1, 24),
        groupLaw.AffineCoordinates(2, 6),
        groupLaw.AffineCoordinates(2, 23),
        groupLaw.AffineCoordinates(3, 1),
        groupLaw.AffineCoordinates(3, 28),
        groupLaw.AffineCoordinates(4, 10),
        groupLaw.AffineCoordinates(4, 19),
        groupLaw.AffineCoordinates(5, 7),
        groupLaw.AffineCoordinates(5, 22),
        groupLaw.AffineCoordinates(6, 12),
        groupLaw.AffineCoordinates(6, 17),
        groupLaw.AffineCoordinates(8, 10),
        groupLaw.AffineCoordinates(8, 19),
        groupLaw.AffineCoordinates(10, 4),
        groupLaw.AffineCoordinates(10, 25),
        groupLaw.AffineCoordinates(13, 6),
        groupLaw.AffineCoordinates(13, 23),
        groupLaw.AffineCoordinates(14, 6),
        groupLaw.AffineCoordinates(14, 23),
        groupLaw.AffineCoordinates(15, 2),
        groupLaw.AffineCoordinates(15, 27),
        groupLaw.AffineCoordinates(16, 2),
        groupLaw.AffineCoordinates(16, 27),
        groupLaw.AffineCoordinates(17, 10),
        groupLaw.AffineCoordinates(17, 19),
        groupLaw.AffineCoordinates(19, 13),
        groupLaw.AffineCoordinates(19, 16),
        groupLaw.AffineCoordinates(20, 3),
        groupLaw.AffineCoordinates(20, 26),
        groupLaw.AffineCoordinates(24, 7),
        groupLaw.AffineCoordinates(24, 22),
        groupLaw.AffineCoordinates(27, 2),
        groupLaw.AffineCoordinates(27, 27))
      val points = coordinates.map(coord => groupLaw.makePoint(coord, curve1))
      val randomPoint = this.curve1.randomPoint

      tracer.out().printfIndentln("randomPoint = %s", randomPoint)
      assert(points.contains(randomPoint))
    }

    testWithTracing(this, "Draw") {
      val tracer = getCurrentTracer()

      val file = new File("." + File.separator + "plots" + File.separator + "plot.txt")
      this.curve1.draw(file)
    }

    def computePoints(curve: AffineCurve): Set[AffinePoint] = {
      withTracer("Set[AffinePoint]", this, "computePoints(curve: AffineCurve)") {
        val points = scala.collection.mutable.Set.empty[AffinePoint]
        val legendreSymbol: LegendreSymbol = new EulersCriterion(curve.p)
        val solver: QuadraticResidue = new QuadraticResidue(curve.p)
        (0 until curve.p).map(x => {
          val yquadrat = curve.evaluateCurveEquation(x)
          val value = legendreSymbol.compute(yquadrat)
          if (value == 1) {
            val (y1, y2) = solver.solve(yquadrat)
            points += this.groupLaw.makePoint(this.groupLaw.AffineCoordinates(x, y1), curve)
            points += this.groupLaw.makePoint(this.groupLaw.AffineCoordinates(x, y2), curve)
          }
          else if (value == 0)
            points += this.groupLaw.makePoint(this.groupLaw.AffineCoordinates(x, 0), curve)
        })
        points.map(point => point).toSet
      }
    }
    
    testWithTracing(this, "Group Structure") {
      val tracer = getCurrentTracer()
      
      val curve = groupLaw.makeCurve(groupLaw.OddCharCoefficients(4, 20), groupLaw.PrimeField(37))
      val points = computePoints(curve)
      val order = points.size + 1
      
      tracer.out().printfIndentln("points(%d) = %s", int2Integer(order), points)
      
      val pointOrders = points.map(point => {
        val range = 1 to order
        val scalar = range.find(i => {
          val element = point.multiply(i)
          element match {
            case element: this.groupLaw.AffinePoint    => false
            case element: this.groupLaw.NeutralElement => true
          }
        })
        (point, scalar.get)
      })
      
      pointOrders.map(pointOrder => {
        tracer.out().printfIndentln("Order of %s = %d", pointOrder._1, pointOrder._2: Integer)
      })
      
      val groupOrderCalculus = new LegendreMethod
      
      assert(order == curve.computeOrder(groupOrderCalculus), "Wrong order.")
    }
    
    testWithTracing(this, "Group Order (1)") {
      val tracer = getCurrentTracer()
      
      val shanksMestre = new ShanksMestre
      val legendreMethod = new LegendreMethod
      val order2 = this.curve2.computeOrder(legendreMethod)
      val trials = 2
      val check = (0 until trials).exists(i => {
        try {
          val order1 = shanksMestre.computeOrder(this.curve2)
          val point = this.curve2.randomPoint

          tracer.out().printfIndentln("ShanksMestre(%1$s) = %2$s, %3$s*%2$s=%4$s", this.curve2, order1, point, (point multiply order1))
          tracer.out().printfIndentln("LegendreMethod(%1$s) = %2$s, %3$s*%2$s=%4$s", this.curve2, order2, point, (point multiply order1))
          if (order1 != order2)
            tracer.logMessage(LogLevel.WARNING, "Shanks-Mestre failed.", getClass, "Group Order (1)")

          order1 == order2
        }
        catch {
          case ex: Throwable => {
            tracer.logException(LogLevel.ERROR, ex, getClass, "Group Order (2)")
            false
          }
        }
      })
      
      assert(check, "All trials failed.")
    }
    
    testWithTracing(this, "Group Order (2)") {
      val tracer = getCurrentTracer()
      tracer.out().printfIndentln("PrimeBase.primes.size = %d", PrimeBase.primes.size: Integer)

      val randomGenerator = new RandomGenerator
      val lowerPrimeLimit = 1000
      val upperPrimeLimit = 100000
      val index = randomGenerator.intStream(PrimeBase.primes.size)
        .find(index => {
          tracer.out().printfIndentln("PrimeBase.primes(%d) = %d", index: Integer, PrimeBase.primes(index): Integer)
          PrimeBase.primes(index) > lowerPrimeLimit && PrimeBase.primes(index) < upperPrimeLimit
        }).get
      val prime = PrimeBase.primes(index)
      val pairedIntStream = randomGenerator.intStream(prime).zip(randomGenerator.intStream(prime))
      val (a, b) = pairedIntStream.find(coefficients => this.groupLaw.isCurve(coefficients._1, coefficients._2, prime)).get
      val coefficients = this.groupLaw.OddCharCoefficients(a, b)
      val curve = this.groupLaw.makeCurve(coefficients, this.groupLaw.PrimeField(prime))
      
      tracer.out().printfIndentln("curve = %s", curve)
      
      val legendreMethod = new LegendreMethod
      val orderByLegendreMethod = curve.computeOrder(legendreMethod)
      
      tracer.out().printfIndentln("orderByLegendreMethod = %s", orderByLegendreMethod)
      
      val trials = 2
      val check = (0 until trials).exists(i => {
        val point = curve.randomPoint
        val element = point multiply orderByLegendreMethod
        
        tracer.out().printfIndentln("%s*%s = %s", point, orderByLegendreMethod, element)
        assert(element.isNeutralElement, "Expected the NeutralElement.")

        val shanksMestre = new ShanksMestre
        try {
          val orderByShanksMestre = curve.computeOrder(shanksMestre)

          tracer.out().printfIndentln("orderByShanksMestre = %1$s, %2$s*%1$s = %3$s", orderByShanksMestre, point, (point multiply orderByShanksMestre))
          if (orderByShanksMestre != orderByLegendreMethod)
            tracer.logMessage(LogLevel.WARNING, "Shanks-Mestre failed.", getClass, "Group Order (2)")

          orderByLegendreMethod == orderByShanksMestre
        }
        catch {
          case ex: Throwable => {
            tracer.logException(LogLevel.ERROR, ex, getClass, "Group Order (2)")
            false
          }
        }
      })
      
      assert(check, "All trials failed.")
    }
    
    ignore(this, "Experiment") {
      val tracer = getCurrentTracer()
      
      val legendreMethod = new LegendreMethod
      val order = this.curve2.computeOrder(legendreMethod)
      val traceOfFrobenius = (order - this.curve2.p - 1).mod(this.curve2.p)
      val point = this.curve2.randomPoint
      val (xquadrat, yquadrat) = ((point.x*point.x).mod(this.curve2.p), (point.y*point.y).mod(this.curve2.p))
      val frobeniusPoint1 = this.groupLaw.makePoint(this.groupLaw.AffineCoordinates(xquadrat, yquadrat), this.curve2)
      val frobeniusPoint2 = point multiply traceOfFrobenius
      val frobeniusPoint3 = point multiply this.curve2.p
      val checkPoint = frobeniusPoint1 add frobeniusPoint2 add frobeniusPoint3
      
      tracer.out().printfIndentln("%s - %s + %s = %s", frobeniusPoint1, frobeniusPoint2, frobeniusPoint3, checkPoint)
      
      val solver = new QuadraticResidue(this.curve2.p)
      val y = solver.solve(this.curve2.evaluateCurveEquation(xquadrat))
      
      tracer.out().printfIndentln("test(%s, %s)", xquadrat, y)
    }
    
    testWithTracing(this, "Fixed Point Multiplication") {
      val tracer = getCurrentTracer()
      
      val point = this.curve2.randomPoint
      val fixedPointMultiplication = new FixedPointBinaryMethod(point)
      
      tracer.out().printfIndentln("this.curve2 = %s", this.curve2)
      tracer.out().printfIndentln("%s: fixedPointMultiplication.multiplies = %s", point, fixedPointMultiplication.multiplies)

      val test = fixedPointMultiplication.multiplies.forall({
        case (index, multiply) => {
          val power = BigInt(2).modPow(index, this.curve2.p)
          val checkPoint = point multiply power
          tracer.out().printfIndentln("(2^%d, %s) =?= (%s, %s)", index: Integer, multiply, power, checkPoint)
          checkPoint == multiply        
        }
      })
      
      assert(test, "Wrong multiplies.")
      
      val randomGenerator = new RandomGenerator
      val scalar = randomGenerator.bigIntStream(this.curve2.p.bitLength*2, this.curve2.p).head
      val productByFixedPointMultiplication = fixedPointMultiplication.multiply(scalar)
      val product = point multiply scalar
      
      tracer.out().printfIndentln("%s*%s = %s", point, scalar, productByFixedPointMultiplication)
      tracer.out().printfIndentln("(%s == %s) = %b", productByFixedPointMultiplication, product, (product == productByFixedPointMultiplication): java.lang.Boolean)
      assert(product == productByFixedPointMultiplication, "Wrong product.")
    }
  }
}
