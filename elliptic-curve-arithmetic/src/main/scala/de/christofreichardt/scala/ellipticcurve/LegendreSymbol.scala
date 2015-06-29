package de.christofreichardt.scala.ellipticcurve

trait LegendreSymbol {
  val p: BigInt
  require(p.isProbablePrime(Constants.CERTAINTY))
  
  def isQuadraticResidue(a: BigInt): Boolean
  def compute(a: BigInt): Int = {
    if (a.mod(this.p) == BigInt(0)) 0
    else if (isQuadraticResidue(a)) 1
    else -1
  }
}

class EulersCriterion(p1: BigInt) extends {
  val p = p1
} with LegendreSymbol {
  def isQuadraticResidue(a: BigInt): Boolean = a.mod(this.p).modPow((p - 1)/2, p) == BigInt(1)
}
