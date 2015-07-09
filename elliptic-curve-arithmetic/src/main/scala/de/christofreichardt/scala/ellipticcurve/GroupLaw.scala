package de.christofreichardt.scala.ellipticcurve

import java.math.BigInteger

abstract class GroupLaw {
  trait Curve
  trait Coordinates
  trait Coefficients
  trait FiniteField
  
  type ThePoint <: Point
  type TheCurve <: Curve
  type TheCoefficients <: Coefficients
  type TheFiniteField <: FiniteField
  type TheCoordinates <: Coordinates
  
  trait Element {
    def isNeutralElement: Boolean
    def negate: Element
    def add(element: Element): Element = {
      element match {
        case neutralElement: NeutralElement => add(neutralElement)
        case point: ThePoint                => add(point)
      }
    }
    def add(element: ThePoint): Element
    def add(element: NeutralElement) = this
    def multiply(scalar: BigInt): Element
    def multiply(scalar: BigInteger): Element = multiply(BigInt(scalar))
  }

  class NeutralElement extends Element {
    override def isNeutralElement = true
    override def negate = this
    override def add(element: ThePoint) = element
    override def multiply(scalar: BigInt) = this
    override def toString() = "NeutralElement"
  }
  
  trait Point extends Element {
    override def isNeutralElement = false
  }
  
  def makeCurve(coefficients: TheCoefficients, finiteField: TheFiniteField): TheCurve
  def makePoint(coordinates: TheCoordinates, curve: TheCurve): ThePoint
  def makeNeutralElement: NeutralElement = new NeutralElement
  
  class NeutralElementException(msg: String) extends RuntimeException(msg)
}
