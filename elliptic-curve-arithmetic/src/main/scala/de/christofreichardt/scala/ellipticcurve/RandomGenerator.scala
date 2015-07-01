package de.christofreichardt.scala.ellipticcurve

import scala.BigInt
import scala.Stream
import scala.util.Random

/**
 * @author Christof Reichardt
 */
class RandomGenerator(secureRandom: java.security.SecureRandom) {
  val random = new Random(secureRandom)
  
  def this() = this(new java.security.SecureRandom)
  
  final def bigIntStream(numberOfBits: Int, p: BigInt): Stream[BigInt] = {
    val next = BigInt(numberOfBits, random).mod(p)
    Stream.cons(next, bigIntStream(numberOfBits, p))
  }
  
  final def bigPrimeStream(numberOfBits: Int): Stream[BigInt] = {
    val next = BigInt(numberOfBits, Constants.CERTAINTY, random)
    Stream.cons(next, bigPrimeStream(numberOfBits))
  }
  
  final def bitStream: Stream[Boolean] = {
    val next = this.random.nextBoolean()
    Stream.cons(next, bitStream)
  }
  
  final def intStream(upperLimit: Int): Stream[Int] = {
    val next = this.random.nextInt(upperLimit)
    Stream.cons(next, intStream(upperLimit))
  }
}