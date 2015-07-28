package de.christofreichardt.crypto.ecschnorrsignature;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import de.christofreichardt.crypto.ecschnorrsignature.ECSchnorrSigKeyGenParameterSpec.CurveCompilation;
import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import de.christofreichardt.scala.ellipticcurve.GroupLaw.Element;
import de.christofreichardt.scala.ellipticcurve.RandomGenerator;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesWithPrimeField.AffinePoint;
import de.christofreichardt.scala.ellipticcurve.affine.ShortWeierstrass;

public class KeyPairGenerator extends KeyPairGeneratorSpi implements Traceable {
  
  private SecureRandom secureRandom = new SecureRandom();
  private ECSchnorrSigKeyGenParameterSpec ecSchnorrSigKeyGenParameterSpec = new ECSchnorrSigKeyGenParameterSpec(CurveCompilation.NIST, "P-256", true);

  @Override
  public KeyPair generateKeyPair() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("KeyPair", this, "generateKeyPair()");

    try {
      tracer.out().printfIndentln("this.ecSchnorrSigGenParameterSpec = %s", this.ecSchnorrSigKeyGenParameterSpec);
      
      CurveSpec curveSpec;
      switch (this.ecSchnorrSigKeyGenParameterSpec.getCurveCompilation()) {
      case NIST:
        curveSpec = NIST.curves.get(this.ecSchnorrSigKeyGenParameterSpec.getCurveId());
        break;
      case BRAINPOOL:
        curveSpec = BrainPool.curves.get(this.ecSchnorrSigKeyGenParameterSpec.getCurveId());
        break;
      default:
        throw new InvalidParameterException("Unsupported curve compilation.");
      }
      
      AffinePoint gPoint;
      do {
        AffinePoint randomPoint = curveSpec.getCurve().randomPoint(new RandomGenerator(this.secureRandom));
        Element element = randomPoint.multiply(curveSpec.getCoFactor());
        if (!element.isNeutralElement()) {
          gPoint = ShortWeierstrass.elemToAffinePoint(element);
          break;
        }
      } while (true);
      
      BigInteger x;
      do {
        x = new BigInteger(curveSpec.getOrder().bitLength()*2, this.secureRandom).mod(curveSpec.getOrder());
      } while(x.equals(BigInteger.ZERO));
      
      Element element = gPoint.multiply(x);
      assert !element.isNeutralElement();
      AffinePoint hPoint = ShortWeierstrass.elemToAffinePoint(element);
      
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
      
      String curveId = "P-" + keySize;
      if (!NIST.curves.containsKey(curveId))
        throw new InvalidParameterException("Unsupported keysize: " + keySize + ".");
      
      this.ecSchnorrSigKeyGenParameterSpec = new ECSchnorrSigKeyGenParameterSpec(CurveCompilation.NIST, curveId, true);
      this.secureRandom = secureRandom;
    }
    finally {
      tracer.wayout();
    }
  }
  
  @Override
  public void initialize(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "initialize(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom)");

    try {
      this.ecSchnorrSigKeyGenParameterSpec = (ECSchnorrSigKeyGenParameterSpec) algorithmParameterSpec;
      switch (this.ecSchnorrSigKeyGenParameterSpec.getCurveCompilation()) {
      case NIST:
        if (!NIST.curves.containsKey(this.ecSchnorrSigKeyGenParameterSpec.getCurveId()))
          throw new InvalidAlgorithmParameterException("Unknown curve: " + this.ecSchnorrSigKeyGenParameterSpec.getCurveId());
        break;
      case BRAINPOOL:
        if (!BrainPool.curves.containsKey(this.ecSchnorrSigKeyGenParameterSpec.getCurveId()))
          throw new InvalidAlgorithmParameterException("Unknown curve: " + this.ecSchnorrSigKeyGenParameterSpec.getCurveId());
        break;
      default:
        throw new InvalidAlgorithmParameterException("Unsupported curve compilation.");
      }
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
