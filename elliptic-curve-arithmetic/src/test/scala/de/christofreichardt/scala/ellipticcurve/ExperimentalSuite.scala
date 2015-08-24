package de.christofreichardt.scala.ellipticcurve

import de.christofreichardt.scalatest.MyFunSuite
import scala.annotation.tailrec
import de.christofreichardt.scala.ellipticcurve.projective.JacobianShortWeierstrass

class ExperimentalSuite extends MyFunSuite {
  
  testWithTracing(this, "Simple Ladder") {
    val tracer = getCurrentTracer()
    
    val multiplier = BigInt(13)
    val multiplicand = BigInt(5)
    
    tracer.out().printfIndentln("bitLength(%s) = %d, %s", multiplier, multiplier.bitLength: Integer, multiplier.toString(2))
    
    def simpleLadder(multiplier: BigInt, multiplicand: BigInt): BigInt = {
      withTracer("BigInt", this, "simpleLadder(multiplier: BigInt, multiplicand: BigInt)") {
        tracer.out().printfIndentln("multiplier = %s", multiplier)
        tracer.out().printfIndentln("multiplicand = %s", multiplicand)
        
        @tailrec
        def multiply(s: BigInt, t: BigInt, i: Int): BigInt = {
          tracer.out().printfIndentln("------------------")
          if (i >= 0) tracer.out().printfIndentln("testBit(%d) = %b", i: Integer, multiplier.testBit(i): java.lang.Boolean)
          tracer.out().printfIndentln("s = %s", s)
          tracer.out().printfIndentln("t = %s", t)
          
          if (i < 0) 
            s
          else {
            val (next_s, next_t): (BigInt, BigInt) =
              if (multiplier.testBit(i)) 
                (s + t, 2*t)
              else 
                (2*s, s + t)
              multiply(next_s, next_t, i - 1)
          }
        }
      
        multiply(BigInt(0), multiplicand, multiplier.bitLength - 1)
      }
    }
    
    def doubleAndAdd(multiplier: BigInt, multiplicand: BigInt): BigInt = {
      withTracer("BigInt", this, "doubleAndAdd(multiplier: BigInt, multiplicand: BigInt)") {
        tracer.out().printfIndentln("multiplier = %s", multiplier)
        tracer.out().printfIndentln("multiplicand = %s", multiplicand)
        
        @tailrec
        def multiply(s: BigInt, i: Int): BigInt = {
          tracer.out().printfIndentln("------------------")
          if (i >= 0) tracer.out().printfIndentln("testBit(%d) = %b", i: Integer, multiplier.testBit(i): java.lang.Boolean)
          tracer.out().printfIndentln("s = %s", s)

          if (i < 0)
            s
          else {
            val double = 2 * s
            val next_s =
              if (multiplier.testBit(i))
                double + multiplicand
              else
                double
            multiply(next_s, i - 1)
          }
        }
        
        multiply(BigInt(0), multiplier.bitLength - 1)
      }
    }
    
    val product1 = simpleLadder(multiplier, multiplicand)
    val product2 = doubleAndAdd(multiplier, multiplicand)
    
    tracer.out().printfIndentln("product1 = %s, product2 = %s", product1, product2)
  }
  
  testWithTracing(this, "Projective Point Addition") {
    val tracer = getCurrentTracer()
    
    val groupLaw = JacobianShortWeierstrass
    val projectiveCurve = groupLaw.makeCurve(groupLaw.OddCharCoefficients(4, 20), groupLaw.PrimeField(29))
    val projectivePoint = groupLaw.makePoint(groupLaw.ProjectiveCoordinates(1, 5, 1), projectiveCurve)
    val p1 = projectivePoint.add(projectivePoint)
    
    tracer.out().printfIndentln("p1 = %s", p1)
    tracer.out().printfIndentln("p1.toAffinePoint = %s", groupLaw.elemToAffinePoint(p1).toAffinePoint)
    
    val p2 = p1.add(projectivePoint)
    
    tracer.out().printfIndentln("p2 = %s", p2)
    tracer.out().printfIndentln("p2.toAffinePoint = %s", groupLaw.elemToAffinePoint(p2).toAffinePoint)
  }
  
  testWithTracing(this, "Projective Point Multiplication") {
    val tracer = getCurrentTracer()
    
    val groupLaw = JacobianShortWeierstrass
    val projectiveCurve = groupLaw.makeCurve(groupLaw.OddCharCoefficients(4, 20), groupLaw.PrimeField(29))
    val projectivePoint = groupLaw.makePoint(groupLaw.ProjectiveCoordinates(1, 5, 1), projectiveCurve)
    val product = projectivePoint.multiply(37)
    
    tracer.out().printfIndentln("product = %s", product)
//    tracer.out().printfIndentln("product.toAffinePoint = %s", groupLaw.elemToAffinePoint(product).toAffinePoint)
  }
}