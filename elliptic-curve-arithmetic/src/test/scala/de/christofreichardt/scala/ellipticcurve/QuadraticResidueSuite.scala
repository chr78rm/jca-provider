/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package de.christofreichardt.scala.ellipticcurve

import de.christofreichardt.scalatest.MyFunSuite
import scala.util.Random

class QuadraticResidueSuite extends MyFunSuite {
  val randomGenerator = new RandomGenerator

  testWithTracing(this, "Case p = 3 (mod 4)") {
    val tracer = getCurrentTracer()

    val p = randomGenerator.bigPrimeStream(16).find(p => p.mod(BigInt(4)) == BigInt(3)).get
    val n = randomGenerator.bigIntStream(p.bitLength * 2, p).find(n => n != BigInt(0) && new EulersCriterion(p).isQuadraticResidue(n)).get

    tracer.out().printfIndentln("p = %s", p)
    tracer.out().printfIndentln("n = %s", n)

    val solver = new QuadraticResidue(p)
    val squareRoots = solver.solve(n)

    tracer.out().printfIndentln("squareRoots = %s", squareRoots)
    assert(squareRoots._1.modPow(BigInt(2), p) == n && squareRoots._2.modPow(BigInt(2), p) == n)
  }

  testWithTracing(this, "Case p = 5 (mod 8)") {
    val tracer = getCurrentTracer()

    val p = randomGenerator.bigPrimeStream(16).find(p => p.mod(BigInt(8)) == BigInt(5)).get
    val n = randomGenerator.bigIntStream(p.bitLength * 2, p).find(n => n != BigInt(0) && new EulersCriterion(p).isQuadraticResidue(n)).get

    tracer.out().printfIndentln("p = %s", p)
    tracer.out().printfIndentln("n = %s", n)

    val solver = new QuadraticResidue(p)
    val squareRoots = solver.solve(n)

    tracer.out().printfIndentln("squareRoots = %s", squareRoots)
    assert(squareRoots._1.modPow(BigInt(2), p) == n && squareRoots._2.modPow(BigInt(2), p) == n)
  }

  testWithTracing(this, "Case p = 1 (mod 8)") {
    val tracer = getCurrentTracer()

    val TESTS = 10
    (0 until TESTS).foreach(i => {
      tracer.out().printfIndentln("=> %d. run", i: Integer)
      
      val p = randomGenerator.bigPrimeStream(16).find(p => p.mod(BigInt(8)) == BigInt(1)).get
      val n = randomGenerator.bigIntStream(p.bitLength * 2, p).find(n => n != BigInt(0) && new EulersCriterion(p).isQuadraticResidue(n)).get
  
      tracer.out().printfIndentln("p = %s", p)
      tracer.out().printfIndentln("n = %s", n)
  
      val solver = new QuadraticResidue(p)
      val squareRoots = solver.solve(n)
  
      tracer.out().printfIndentln("squareRoots = %s", squareRoots)
      assert(squareRoots._1.modPow(BigInt(2), p) == n && squareRoots._2.modPow(BigInt(2), p) == n)
    })
  }
}
