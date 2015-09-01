package de.christofreichardt.crypto.ecschnorrsignature;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import scala.math.BigInt;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesWithPrimeField.AffineCoordinates;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesWithPrimeField.AffinePoint;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesWithPrimeField.PrimeField;
import de.christofreichardt.scala.ellipticcurve.affine.ShortWeierstrass;
import de.christofreichardt.scala.ellipticcurve.affine.ShortWeierstrass.OddCharCoefficients;

public class NIST {
  static public final Map<String, CurveSpec> curves = new HashMap<>();
  static public final String[] curveIds = {"P-192", "P-224", "P-256", "P-384", "P-521"};
  static {
    BigInteger a = BigInteger.valueOf(-3);
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
    BigInteger[] x = {
        new BigInteger("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", 16),
        new BigInteger("b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21", 16),
        new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
        new BigInteger("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", 16),
        new BigInteger("c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 16),
        };
    BigInteger[] y = {
        new BigInteger("07192b95ffc8da78631011ed6b24cdd573f977a11e794811", 16),
        new BigInteger("bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34", 16),
        new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
        new BigInteger("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16),
        new BigInteger("11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", 16),
        };
    for (int i=0; i<curveIds.length; i++) {
      PrimeField primeField = ShortWeierstrass.makePrimeField(new BigInt(p[i]));
      OddCharCoefficients coefficients = new OddCharCoefficients(new BigInt(a).mod(primeField.p()), new BigInt(b[i]));
      ShortWeierstrass.Curve curve = ShortWeierstrass.makeCurve(coefficients, primeField);
      AffineCoordinates affineCoordinates = ShortWeierstrass.makeAffineCoordinates(new BigInt(x[i]), new BigInt(y[i]));
      AffinePoint point = ShortWeierstrass.makePoint(affineCoordinates, curve);
      CurveSpec curveSpec = new CurveSpec(curve, orders[i], BigInteger.ONE, point);
      curves.put(curveIds[i], curveSpec);
    }
  }
}
