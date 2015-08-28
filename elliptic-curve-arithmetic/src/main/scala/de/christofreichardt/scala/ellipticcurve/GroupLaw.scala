package de.christofreichardt.scala.ellipticcurve

import java.math.BigInteger
import de.christofreichardt.scala.diagnosis.Tracing
import de.christofreichardt.diagnosis.AbstractTracer
import de.christofreichardt.diagnosis.TracerFactory
import scala.annotation.tailrec

abstract class GroupLaw {
  trait AbstractCurve
  trait Coordinates
  trait Coefficients
  trait FiniteField
  
  type ThePoint <: AbstractPoint
  type TheCurve <: AbstractCurve
  type TheCoefficients <: Coefficients
  type TheFiniteField <: FiniteField
  type TheCoordinates <: Coordinates

  trait Element {
    def isNeutralElement: Boolean
    def negate: Element
    def add(element: Element): Element = {
      element match {
        case neutralElement: NeutralElement => add(neutralElement)
        case point: ThePoint @unchecked     => add(point)
      }
    }
    def add(element: ThePoint): Element
    def add(element: NeutralElement) = this
    def multiply(scalar: BigInt): Element
    def multiply(scalar: BigInteger): Element = multiply(BigInt(scalar))
    def toPoint: AbstractPoint
  }

  class NeutralElement extends Element with Equals {
    override def isNeutralElement = true
    override def negate = this
    override def add(element: ThePoint) = element
    override def multiply(scalar: BigInt) = this
    override def toString() = "NeutralElement"
    override def toPoint = throw new NeutralElementException("Not really a point.")

    def canEqual(other: Any) = {
      other.isInstanceOf[GroupLaw.this.NeutralElement]
    }

    override def equals(other: Any) = {
      other match {
        case that: GroupLaw.this.NeutralElement => that.canEqual(NeutralElement.this)
        case _ => false
      }
    }

    override def hashCode() = {
      val prime = 41
      prime
    }
  }
  
  trait AbstractPoint extends Element {
    override def isNeutralElement = false
    override def toPoint = this
  }
  
  trait PointMultiplication extends Tracing {
    def multiply(m: BigInt, point: AbstractPoint): Element
    
    override def getCurrentTracer(): AbstractTracer = {
      try {
        TracerFactory.getInstance().getDefaultTracer
      }
      catch {
        case ex: TracerFactory.Exception => TracerFactory.getInstance().getDefaultTracer
      }
    }
  }
  
  trait UnknownPointMultiplication extends PointMultiplication

  class BinaryMethod extends UnknownPointMultiplication {
    override def multiply(multiplier: BigInt, point: AbstractPoint): Element = {
      val tracer = getCurrentTracer()
      
      @tailrec
      def multiply(q: Element, i: Int): Element = {
        tracer.out().printfIndentln("i = %d", int2Integer(i))
        tracer.out().printfIndentln("q = %s", q)
        tracer.out().flush()

        if (i == 0) {
          q
        }
        else {
          val double = q.add(q)
          val sum =
            if (multiplier.testBit(i - 1)) point add double
            else double
          multiply(sum, i - 1)
        }
      }
      
      withTracer("Element", this, "multiply(m: BigInt, point: AffinePoint)") {
        tracer.out().printfIndentln("multiplier(%d) = %s", multiplier.bitLength: Integer, multiplier)
        tracer.out().printfIndentln("point = %s", point)

        if (multiplier == BigInt(0)) new NeutralElement
        else multiply(new NeutralElement, multiplier.bitLength)
      }
    }
  }
  
  class MontgomeryLadder extends UnknownPointMultiplication {
    override def multiply(multiplier: BigInt, point: AbstractPoint): Element = {
      val tracer = getCurrentTracer()
      
      @tailrec
      def multiply(s: Element, t: Element, i: Int): Element = {
        tracer.out().printfIndentln("------------------")
        if (i >= 0) tracer.out().printfIndentln("testBit(%d) = %b", i: Integer, multiplier.testBit(i): java.lang.Boolean)
        tracer.out().printfIndentln("s = %s", s)
        tracer.out().printfIndentln("t = %s", t)

        if (i < 0)
          s
        else {
          val (next_s, next_t): (Element, Element) =
            if (multiplier.testBit(i))
              (s add t, t add t)
            else
              (s add s, s add t)
          multiply(next_s, next_t, i - 1)
        }
      }
      
      withTracer("Element", this, "multiply(m: BigInt, point: AffinePoint)") {
        tracer.out().printfIndentln("multiplier(%d) = %s", multiplier.bitLength: Integer, multiplier)
        tracer.out().printfIndentln("point = %s", point)
        
        multiply(new NeutralElement, point, multiplier.bitLength - 1)
      }
    }
  }

  class MontgomeryLadder2 extends UnknownPointMultiplication {
    override def multiply(multiplier: BigInt, point: AbstractPoint): Element = {
      val tracer = getCurrentTracer()
      
      @tailrec
      def multiply(element: Element, i: Int): Element = {
        tracer.out().printfIndentln("------------------")
        if (i >= 0) tracer.out().printfIndentln("testBit(%d) = %b", i: Integer, multiplier.testBit(i): java.lang.Boolean)
        tracer.out().printfIndentln("element = %s", element)

        if (i < 0)
          element
        else {
          val next: scala.collection.mutable.Map[Boolean, Element] = scala.collection.mutable.HashMap.empty[Boolean, Element]
          next += (false -> element.add(element))
          next += (true -> point.add(next(false)))
          multiply(next(multiplier.testBit(i)), i - 1)
        }
      }
      
      withTracer("Element", this, "multiply(m: BigInt, point: AffinePoint)") {
        tracer.out().printfIndentln("multiplier(%d) = %s", multiplier.bitLength: Integer, multiplier)
        tracer.out().printfIndentln("point = %s", point)
        
        multiply(new NeutralElement, multiplier.bitLength - 1)
      }
    }
  }

  
  def makeCurve(coefficients: TheCoefficients, finiteField: TheFiniteField): TheCurve
  def makePoint(coordinates: TheCoordinates, curve: TheCurve): ThePoint
  def makeNeutralElement: NeutralElement = new NeutralElement
  
  class NeutralElementException(msg: String) extends RuntimeException(msg)
}
