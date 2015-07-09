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
  }
}