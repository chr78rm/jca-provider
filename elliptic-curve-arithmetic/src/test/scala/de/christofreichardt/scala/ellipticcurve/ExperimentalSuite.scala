package de.christofreichardt.scala.ellipticcurve

import de.christofreichardt.scalatest.MyFunSuite
import scala.annotation.tailrec

class ExperimentalSuite extends MyFunSuite {
  
  testWithTracing(this, "Montgomery Ladder") {
    val tracer = getCurrentTracer()
    
    val multiplier = BigInt(15)
    val multiplicand = BigInt(5)
    
    tracer.out().printfIndentln("bitLength(%s) = %d, %s", multiplier, multiplier.bitLength: Integer, multiplier.toString(2))
    
    def simpleLadder(multiplier: BigInt, multiplicand: BigInt): BigInt = {
      withTracer("BigInt", this, "simpleLadder(multiplier: BigInt, multiplicand: BigInt)") {
        tracer.out().printfIndentln("multiplier = %s", multiplier)
        tracer.out().printfIndentln("multiplicand = %s", multiplicand)
        
        @tailrec
        def multiply(s: BigInt, t: BigInt, i: Int): BigInt = {
          tracer.out().printfIndentln("i = %d", i: Integer)
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
          tracer.out().printfIndentln("i = %d", i: Integer)
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
}