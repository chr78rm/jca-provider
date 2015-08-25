/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package de.christofreichardt.scala.ellipticcurve

import de.christofreichardt.scala.diagnosis.Tracing
import scala.util.Random
import de.christofreichardt.diagnosis.AbstractTracer
import de.christofreichardt.diagnosis.TracerFactory
import scala.annotation.tailrec

class QuadraticResidue(val p: BigInt) extends Tracing {
  require(p.isProbablePrime(Constants.CERTAINTY), p + " isn't prime.")

  def solve(a: BigInt): (BigInt, BigInt) = {
    require(a == 0  ||  new EulersCriterion(p).isQuadraticResidue(a), a + " isn't a quadratic residue.")
    
    if (a == 0) 
      (0,0)
    else if (p.mod(BigInt(4)) == BigInt(3)) {
      val x1 = a.modPow((p + BigInt(1)) / BigInt(4), p)
      val x2 = (-x1).mod(p)
      (x1, x2)
    } 
    else if (p.mod(BigInt(8)) == BigInt(5)) {
      if (a.modPow((p - BigInt(1)) / BigInt(4), p) == BigInt(1)) {
        val x1 = a.modPow((p + BigInt(3)) / BigInt(8), p)
        val x2 = (-x1).mod(p)
        (x1, x2)
      } 
      else {
        val x1 = (2 * a * (4 * a).modPow((p - BigInt(5)) / BigInt(8), p)).mod(this.p)
        val x2 = (-x1).mod(p)
        (x1, x2)
      }
    } 
    else
      tonelliAndShanks(a)
  }

  private def tonelliAndShanks(a: BigInt): (BigInt, BigInt) = {
    val randomGenerator = new RandomGenerator
    
    @tailrec
    def factorTwoExp(n: BigInt, exp: Int): (BigInt, Int) = {
      if (n.mod(BigInt(2)) != BigInt(0)) (n, exp)
      else factorTwoExp(n/BigInt(2), exp + 1)
    }
    
    @tailrec
    def square(n: BigInt, i: BigInt): BigInt = {
      if (i == 0) n
      else square((n*n).mod(this.p), i - 1)
    }
    
    @tailrec
    def search(r: BigInt, t: BigInt, m: BigInt, c: BigInt): BigInt = {
      val tracer = getCurrentTracer()
      tracer.out().printfIndentln("--search----> r=%s, t=%s, m=%s, c=%s --", r, t, m, c)
      if (t == 1) r
      else {
        val test = (BigInt(1) until m).find(i => square(t, i) == BigInt(1)) // ATTENTION: has failed once
        assert(test.isDefined, "Unable to extract an i with t^(2^i) = 1 (mod p)")
        val i = test.get
        val b = square(c, m - i - 1)
        search((r*b).mod(this.p), (t*(b*b).mod(this.p)).mod(this.p), i, (b*b).mod(this.p))
      }
    }
    
    withTracer("(BigInt, BigInt)", this, "tonelliAndShanks") {
      val tracer = getCurrentTracer()
      tracer.out().printfIndentln("a = %s", a)
      
      val z = randomGenerator.bigIntStream(p.bitLength*2, p).find(r => new EulersCriterion(p).compute(r) == -1).get
      val (q,e) = factorTwoExp(p - 1, 0)
      val r = a.modPow((q + 1)/2, this.p)
      val t = a.modPow(q, this.p)
      val m = e
      val c = z.modPow(q, this.p)
      
      tracer.out().printfIndentln("z = %s", z)
      tracer.out().printfIndentln("e = %d", int2Integer(e))
      tracer.out().printfIndentln("q = %s", q)
      tracer.out().printfIndentln("r = %s", r)
      tracer.out().printfIndentln("t = %s", t)
      tracer.out().printfIndentln("m = %s", int2Integer(m))
      tracer.out().printfIndentln("c = %s", c)
      
      val x1 = search(r, t, m, c)
      val x2 = (-x1).mod(p)
      (x1,x2)
    }
  }
  
  override def getCurrentTracer(): AbstractTracer = {
    try {
      TracerFactory.getInstance().getTracer("TestTracer")
    }
    catch {
      case ex: TracerFactory.Exception => TracerFactory.getInstance().getDefaultTracer
    }
  }
}
