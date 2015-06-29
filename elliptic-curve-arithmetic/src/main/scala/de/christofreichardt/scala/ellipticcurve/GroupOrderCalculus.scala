package de.christofreichardt.scala.ellipticcurve

package affine {

  import de.christofreichardt.scala.diagnosis.Tracing
  import scala.util.Random
  import scala.annotation.tailrec
  import de.christofreichardt.diagnosis.AbstractTracer
  import de.christofreichardt.diagnosis.TracerFactory
  import java.math.MathContext
  import java.math.RoundingMode
  import AffineCoordinatesOddCharacteristic.AffineCurve
  import AffineCoordinatesOddCharacteristic.AffinePoint
  import AffineCoordinatesOddCharacteristic.Element
  import AffineCoordinatesOddCharacteristic.elemToAffinePoint

  class LegendreMethod extends AffineCoordinatesOddCharacteristic.GroupOrderCalculus {
    def computeOrder(curve: this.groupLaw.AffineCurve): BigInt = {
      val legendreSymbol: LegendreSymbol = new EulersCriterion(curve.p)
      val range = BigInt(0) until curve.p
      val ap = range.foldLeft(BigInt(0))((result, x) => {
        val yquadrat = curve.evaluateCurveEquation(x)
        result + legendreSymbol.compute(yquadrat)
      })
      val (lowerLimit, upperLimit, _) = hasseTheorem(curve)
      val order = curve.p + 1 + ap
      assert(order >= lowerLimit  &&  order <= upperLimit, order + " isn't within the bounds of Hasse's theorem.")
      order
    }
  }

  class ShanksMestre extends AffineCoordinatesOddCharacteristic.GroupOrderCalculus with Tracing {
    def computeOrder(curve: AffineCurve): BigInt = {
      withTracer("BigInt", this, "computeOrder(curve: this.groupLaw.AffineCurve)") {
        val tracer = getCurrentTracer()
        
        val (lowerLimit, upperLimit, pSquared) = hasseTheorem(curve)
        val m = squareRoot(pSquared).round(new MathContext(1, RoundingMode.CEILING)).toBigInt()*BigInt(2)
        val point1 = curve.randomPoint
        
        tracer.out().printfIndentln("point1 = %s", point1)
        tracer.out().printfIndentln("curve = %s", curve)
        tracer.out().printfIndentln("%s <= #E(%s) <= %s", lowerLimit, curve, upperLimit)
        tracer.out().printfIndentln("m = %s", m)
        
        val babySteps = scala.collection.mutable.Map.empty[Element, BigInt]
        (BigInt(0) until m).foreach(r => {
          val product = point1.multiply(r).negate
          babySteps += (product -> r)
        })
        
        tracer.out().printfIndentln("babySteps(%d) = %s", babySteps.size: Integer, babySteps)

        val point2 = point1 multiply lowerLimit
        val hit = (BigInt(1) until m).view
          .map(q => {
            tracer.out().printfIndentln("q = %s", q)
            (q, point1.multiply(q * m).add(point2))
          })
          .find(element => babySteps.get(element._2).isDefined)
        
        tracer.out().printfIndentln("hit = %s", hit)
        
        assert(hit.isDefined, "Group order hasn't been found.")
        
        val r = babySteps.get(hit.get._2).get
        val q = hit.get._1
        val k = q*m + r + lowerLimit
        
        tracer.out().printfIndentln("r = %s, q = %s, k = %s", r, q, k)
        
        val order = k
        assert(order >= lowerLimit  &&  order <= upperLimit, order + " isn't within the bounds of Hasse's theorem.")
        order
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
}
