package de.christofreichardt.scala.ellipticcurve

import de.christofreichardt.scalatest.MyFunSuite
import de.christofreichardt.scala.ellipticcurve.affine.ShortWeierstrass
import de.christofreichardt.scala.ellipticcurve.projective.JacobianShortWeierstrass

class JacobianShortWeierstrassSuite extends MyFunSuite {
  testWithTracing(this, "Jacobian Projective Multiplication (1)") {
    val tracer = getCurrentTracer()

    val projectiveGroupLaw = JacobianShortWeierstrass
    val affineGroupLaw = ShortWeierstrass
    val projectiveCurve = projectiveGroupLaw.makeCurve(projectiveGroupLaw.OddCharCoefficients(4, 20), projectiveGroupLaw.PrimeField(29))
    val projectivePoint = projectiveGroupLaw.makePoint(projectiveGroupLaw.ProjectiveCoordinates(1, 5, 1), projectiveCurve)
    val affineCurve = affineGroupLaw.makeCurve(affineGroupLaw.OddCharCoefficients(4, 20), affineGroupLaw.PrimeField(29))
    val affinePoint = affineGroupLaw.makePoint(affineGroupLaw.AffineCoordinates(1, 5), affineCurve)

    val order = 37
    val testResult =
      (1 until order).forall(m => {
        val element1 = affinePoint.multiply(m)
        val element2 = projectiveGroupLaw.elemToAffinePoint(projectivePoint.multiply(m))

        tracer.out().printfIndentln("(%s == %s) = %b", element1, element2, (element1 == element2): java.lang.Boolean)

        element1 == element2
      })
    assert(testResult, "Wrong product.")

    val element = projectivePoint.multiply(order)
    assert(element.isNeutralElement, "Expected the NeutralElement.")
  }
  
  testWithTracing(this, "Jacobian Projective Multiplication (2)") {
    val tracer = getCurrentTracer()
    
    val a = 10
    val b = BigInt("1343632762150092499701637438970764818528075565078")
    val p = BigInt(2).pow(160) + 7
    val order = BigInt("1461501637330902918203683518218126812711137002561")

    val projectiveGroupLaw = JacobianShortWeierstrass
    val projectiveCurve = projectiveGroupLaw.makeCurve(projectiveGroupLaw.OddCharCoefficients(a, b), projectiveGroupLaw.PrimeField(p))
    
    val affineGroupLaw = ShortWeierstrass
    val affineCurve = affineGroupLaw.makeCurve(affineGroupLaw.OddCharCoefficients(a, b), affineGroupLaw.PrimeField(p))
    
    val TESTS = 10
    val randomGenerator = new RandomGenerator
    val testResult =
      (0 until TESTS).forall(i => {
        tracer.out().printfIndentln("%d. Test", i: Integer)
        
        val randomProjectivePoint = projectiveCurve.randomPoint
        val affinePoint = randomProjectivePoint.toAffinePoint
        val scalar = randomGenerator.bigIntStream(order.bitLength*2, p).head
        
        tracer.out().printfIndentln("randomProjectivePoint = %s", randomProjectivePoint)
        tracer.out().printfIndentln("affinePoint = %s", affinePoint)
        tracer.out().printfIndentln("scalar = %s", scalar)
        
        assert(affinePoint.curve.a == affineCurve.a  &&  affinePoint.curve.b == affineCurve.b  &&  affinePoint.curve.p == affineCurve.p, "Wrong curve.")
        
        val element1 = projectiveGroupLaw.elemToAffinePoint(randomProjectivePoint.multiply(scalar))
        val element2 = affinePoint.multiply(scalar)
        
        tracer.out().printfIndentln("(%s == %s) = %b", element1, element2, (element1 == element2): java.lang.Boolean)
        
        element1 == element2
      })
      
    assert(testResult, "Wrong product.")
  }
}