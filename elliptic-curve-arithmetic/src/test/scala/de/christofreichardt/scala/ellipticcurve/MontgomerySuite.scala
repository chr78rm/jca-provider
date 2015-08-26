package de.christofreichardt.scala.ellipticcurve

import de.christofreichardt.scalatest.MyFunSuite

package affine {
  class MontgomerySuite extends MyFunSuite {
    
    testWithTracing(this, "Montgomery2Weierstrass") {
      val tracer = getCurrentTracer()
      val groupLaw = ShortWeierstrass
      
      def convertCoefficients(coefficients: (BigInt, BigInt), prime: BigInt): (BigInt, BigInt) = {
        val A = coefficients._1
        val B = coefficients._2
        val numeratorA = (3 - A.modPow(2, prime)).mod(prime)
        val denominatorA = (3*B.modPow(2, prime)).mod(prime)
        val numeratorB = (2*A.modPow(3, prime) - 9*A).mod(prime)
        val denominatorB = (27*B.modPow(3, prime)).mod(prime)
        ((numeratorA*denominatorA.modInverse(prime)).mod(prime), (numeratorB*denominatorB.modInverse(prime)).mod(prime))
      }
      
      def convertCoordinates(coordinate: (BigInt, BigInt), coefficients: (BigInt, BigInt), prime: BigInt): (BigInt, BigInt) = {
        val A = coefficients._1
        val B = coefficients._2
        val x = coordinate._1
        val y = coordinate._2
        val transformedX = ((x*B.modInverse(prime)).mod(prime) + (A*(3*B).modInverse(prime))).mod(prime)
        val transformedY = (y*B.modInverse(prime)).mod(prime)
        (transformedX, transformedY)
      }
      
      val montgomeryCoefficients: (BigInt, BigInt) = (117050, 1)
      val prime = BigInt(2).pow(221) - 3
      assert(prime.isProbablePrime(Constants.CERTAINTY))
      val (a, b) = convertCoefficients(montgomeryCoefficients, prime)
      val (x, y) = convertCoordinates((BigInt(4), BigInt("1630203008552496124843674615123983630541969261591546559209027208557")), montgomeryCoefficients, prime)
      val M_221 = groupLaw.makeCurve(groupLaw.OddCharCoefficients(a, b), groupLaw.PrimeField(prime))
      val solver = new QuadraticResidue(prime)
      
      tracer.out().printfIndentln("x = %s, y = %s", x, y)
      tracer.out().printfIndentln("x = %s, y = %s", x, solver.solve(M_221.evaluateCurveEquation(x)))
      
      val basePoint = groupLaw.makePoint(groupLaw.AffineCoordinates(x, y), M_221)
      val point = basePoint.multiply(BigInt("421249166674228746791672110734682167926895081980396304944335052891"))
      
      tracer.out().printfIndentln("point = %s", point)
    }
    
    testWithTracing(this, "Random point") {
      val tracer = getCurrentTracer()
      
      val groupLaw = Montgomery
      val curve = groupLaw.makeCurve(groupLaw.OddCharCoefficients(117050, 1), groupLaw.PrimeField(BigInt(2).pow(221) - 3))
      val randomPoint = curve.randomPoint
      
      tracer.out().printfIndentln("randomPoint = %s", randomPoint)
    }
    
    testWithTracing(this, "P * order(P) = 0") {
      val tracer = getCurrentTracer()
      
      val groupLaw = Montgomery
      val curve = groupLaw.makeCurve(groupLaw.OddCharCoefficients(117050, 1), groupLaw.PrimeField(BigInt(2).pow(221) - 3))
      val basePoint = groupLaw.makePoint(groupLaw.AffineCoordinates(4, BigInt("1630203008552496124843674615123983630541969261591546559209027208557")), curve)
      val order = BigInt("421249166674228746791672110734682167926895081980396304944335052891")
      val product = basePoint multiply order
      val testPoint = groupLaw.makePoint(groupLaw.AffineCoordinates(BigInt("1606415676813498058014924151313595965130794692739589994783694077531"), 
          BigInt("2134935430760076865959898766833545863303276772166762027696560530099")), curve)
      
      tracer.out().printfIndentln("curve = %s", curve)
      tracer.out().printfIndentln("product = %s", product)
      
      assert(product.isNeutralElement, "Expected the NeutralElement.")
    }
    
    testWithTracing(this, "Differential Multiplication") {
      val tracer = getCurrentTracer()
      
      val groupLaw = Montgomery
      val curve = groupLaw.makeCurve(groupLaw.OddCharCoefficients(117050, 1), groupLaw.PrimeField(BigInt(2).pow(221) - 3))
      val basePoint = groupLaw.makePoint(groupLaw.AffineCoordinates(4, BigInt("1630203008552496124843674615123983630541969261591546559209027208557")), curve)
      val double = basePoint add basePoint
      val double2 = basePoint.multiply(2)
      
      tracer.out().printfIndentln("(%s == %s) = %b", double, double2, (double == double2): java.lang.Boolean)
      
      val projectiveGroupLaw = de.christofreichardt.scala.ellipticcurve.projective.Montgomery
      val projectiveCurve = new projectiveGroupLaw.Curve(curve)
      val projectiveBasePoint = new projectiveGroupLaw.Point(basePoint.x, basePoint.y, 1, projectiveCurve)
      val test1 = projectiveBasePoint.multiply(2)
      
      tracer.out().printfIndentln("test1 = %s", test1)
      
      val scalar = 11
      val point = basePoint.multiply(scalar)
      val test2 = projectiveBasePoint.multiply(scalar)
      
      tracer.out().printfIndentln("point = %s", point)
      tracer.out().printfIndentln("test2 = %s", test2)
    }
  }
}