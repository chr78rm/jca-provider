package de.christofreichardt.crypto.ecschnorrsignature;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import scala.math.BigInt;
import de.christofreichardt.scala.ellipticcurve.affine.Montgomery;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesWithPrimeField.AffineCoordinates;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesWithPrimeField.AffinePoint;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesWithPrimeField.PrimeField;
import de.christofreichardt.scala.ellipticcurve.affine.Montgomery.OddCharCoefficients;;

public class SafeCurves {
  static public final Map<String, CurveSpec> curves = new HashMap<>();
  static public final String[] curveIds = {"M-221", "M-383", "M-511"};
  static {
    BigInteger[] orders = { 
        new BigInteger("421249166674228746791672110734682167926895081980396304944335052891"),
        new BigInteger("2462625387274654950767440006258975862817483704404090416746934574041288984234680883008327183083615266784870011007447"),
        new BigInteger("837987995621412318723376562387865382967460363787024586107722590232610251879607410804876779383055508762141059258497448934987052508775626162460930737942299"),
        };
    BigInteger[] p = { 
        (new BigInteger("2").pow(221)).subtract(new BigInteger("3")),
        (new BigInteger("2").pow(383)).subtract(new BigInteger("187")),
        (new BigInteger("2").pow(511)).subtract(new BigInteger("187")),
        };
    BigInteger[] a = { 
        new BigInteger("117050"),
        new BigInteger("2065150"),
        new BigInteger("530438"),
        };
    BigInteger[] b = { 
        BigInteger.ONE,
        BigInteger.ONE,
        BigInteger.ONE,
        };
    BigInteger[] x = { 
        new BigInteger("4"),
        new BigInteger("12"),
        new BigInteger("5"),
        };
    BigInteger[] y = { 
        new BigInteger("1630203008552496124843674615123983630541969261591546559209027208557"),
        new BigInteger("4737623401891753997660546300375902576839617167257703725630389791524463565757299203154901655432096558642117242906494"),
        new BigInteger("2500410645565072423368981149139213252211568685173608590070979264248275228603899706950518127817176591878667784247582124505430745177116625808811349787373477"),
        };
    for (int i=0; i<curveIds.length; i++) {
      OddCharCoefficients coefficients = new OddCharCoefficients(new BigInt(a[i]), new BigInt(b[i]));
      PrimeField primeField = Montgomery.makePrimeField(new BigInt(p[i]));
      Montgomery.Curve curve = Montgomery.makeCurve(coefficients, primeField);
      AffineCoordinates affineCoordinates = Montgomery.makeAffineCoordinates(new BigInt(x[i]), new BigInt(y[i]));
      AffinePoint point = Montgomery.makePoint(affineCoordinates, curve);
      CurveSpec curveSpec = new CurveSpec(curve, orders[i], new BigInteger("8"), point);
      curves.put(curveIds[i], curveSpec);
    }
  }
}
