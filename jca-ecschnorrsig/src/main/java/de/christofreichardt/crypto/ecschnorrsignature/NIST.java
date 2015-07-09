package de.christofreichardt.crypto.ecschnorrsignature;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import scala.math.BigInt;
import de.christofreichardt.scala.ellipticcurve.affine.ShortWeierstrass;
import de.christofreichardt.scala.ellipticcurve.affine.ShortWeierstrass.AffineCurve;
import de.christofreichardt.scala.ellipticcurve.affine.ShortWeierstrass.OddCharCoefficients;
import de.christofreichardt.scala.ellipticcurve.affine.ShortWeierstrass.PrimeField;

public class NIST {
  static public final Map<String, CurveSpec> curves = new HashMap<>();
  static public final String[] curveIds = {"P-192", "P-224", "P-256", "P-384", "P-521"};
  static {
    BigInteger a = BigInteger.valueOf(-3);
//    String[] ids = {"P-192", "P-224", "P-256", "P-384", "P-521"};
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
    for (int i=0; i<curveIds.length; i++) {
      OddCharCoefficients coefficients = new OddCharCoefficients(new BigInt(a), new BigInt(b[i]));
      PrimeField primeField = new PrimeField(new BigInt(p[i]));
      AffineCurve curve = ShortWeierstrass.makeCurve(coefficients, primeField);
      CurveSpec curveSpec = new CurveSpec(curve, orders[i], BigInteger.ONE);
      curves.put(curveIds[i], curveSpec);
    }
  }
}
