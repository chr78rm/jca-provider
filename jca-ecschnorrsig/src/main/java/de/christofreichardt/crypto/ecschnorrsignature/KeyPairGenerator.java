package de.christofreichardt.crypto.ecschnorrsignature;

import java.math.BigInteger;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import scala.math.BigInt;
import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import de.christofreichardt.scala.ellipticcurve.GroupLaw.Element;
import de.christofreichardt.scala.ellipticcurve.RandomGenerator;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesOddCharacteristic;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesOddCharacteristic.AffineCurve;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesOddCharacteristic.AffinePoint;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesOddCharacteristic.OddCharCoefficients;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesOddCharacteristic.PrimeField;

public class KeyPairGenerator extends KeyPairGeneratorSpi implements Traceable {
  static public final Map<Integer, CurveSpec> nistCurves = new HashMap<>();
  static {
    BigInteger a = BigInteger.valueOf(-3);
    Integer[] sizes = {192, 224, 256, 384, 521};
    BigInteger[] orders = { 
        new BigInteger("6277101735386680763835789423176059013767194773182842284081"),
        new BigInteger("26959946667150639794667015087019625940457807714424391721682722368061"),
        new BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369"),
        new BigInteger("39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643"),
        new BigInteger("6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449"),
        };
    BigInteger[] p = {
        new BigInteger("6277101735386680763835789423207666416083908700390324961279"),
        new BigInteger("26959946667150639794667015087019630673557916260026308143510066298881"),
        new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951"),
        new BigInteger("39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319"),
        new BigInteger("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151"),
        };
    BigInteger[] b = {
        new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16),
        new BigInteger("b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4", 16),
        new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16),
        new BigInteger("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16),
        new BigInteger("051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", 16),
        };
    for (int i=0; i<sizes.length; i++) {
      OddCharCoefficients coefficients = new OddCharCoefficients(new BigInt(a), new BigInt(b[i]));
      PrimeField primeField = new PrimeField(new BigInt(p[i]));
      AffineCurve curve = AffineCoordinatesOddCharacteristic.makeCurve(coefficients, primeField);
      CurveSpec curveSpec = new CurveSpec(curve, orders[i], BigInteger.ONE);
      nistCurves.put(sizes[i], curveSpec);
    }
  }
  static public final int DEFAULT_KEYSIZE = 256;
  
  private SecureRandom secureRandom = new SecureRandom();
  private int keySize = DEFAULT_KEYSIZE;

  @Override
  public KeyPair generateKeyPair() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("KeyPair", this, "generateKeyPair()");

    try {
      CurveSpec curveSpec = nistCurves.get(this.keySize);
      AffinePoint gPoint;
      do {
        AffinePoint randomPoint = curveSpec.getCurve().randomPoint(new RandomGenerator(this.secureRandom));
        Element element = randomPoint.multiply(curveSpec.getCoFactor());
        if (!element.isNeutralElement()) {
          gPoint = AffineCoordinatesOddCharacteristic.elemToAffinePoint(element);
          break;
        }
      } while (true);
      
      BigInteger x;
      do {
        x = new BigInteger(curveSpec.getOrder().bitLength()*2, this.secureRandom).mod(curveSpec.getOrder());
      } while(x.equals(BigInteger.ZERO));
      
      Element element = gPoint.multiply(x);
      assert !element.isNeutralElement();
      AffinePoint hPoint = AffineCoordinatesOddCharacteristic.elemToAffinePoint(element);
      
      tracer.out().printfIndentln("gPoint = %s", gPoint);
      tracer.out().printfIndentln("x = %s", x);
      tracer.out().printfIndentln("hPoint = %s", hPoint);
      
      ECSchnorrParams ecSchnorrParams = new ECSchnorrParams(curveSpec, gPoint);
      ECSchnorrPrivateKey ecSchnorrPrivateKey = new ECSchnorrPrivateKey(ecSchnorrParams, x);
      ECSchnorrPublicKey ecSchnorrPublicKey = new ECSchnorrPublicKey(ecSchnorrParams, hPoint);
      
      return new KeyPair(ecSchnorrPublicKey, ecSchnorrPrivateKey);
    }
    finally {
      tracer.wayout();
    }
  }

  @Override
  public void initialize(int keySize, SecureRandom secureRandom) {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "initialize(int keysize, SecureRandom secureRandom)");

    try {
      tracer.out().printfIndentln("keySize = %d", keySize);
      
      this.secureRandom = secureRandom;
      if (nistCurves.containsKey(keySize))
        this.keySize = keySize;
      else
        throw new InvalidParameterException("Unsupported keysize: " + keySize + ".");
    }
    finally {
      tracer.wayout();
    }
  }

  @Override
  public AbstractTracer getCurrentTracer() {
    return TracerFactory.getInstance().getCurrentPoolTracer();
  }
}
