package de.christofreichardt.crypto.ecschnorrsignature;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import de.christofreichardt.crypto.ecschnorrsignature.ECSchnorrSigGenParameterSpec.CurveCompilation;
import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import de.christofreichardt.scala.ellipticcurve.GroupLaw.Element;
import de.christofreichardt.scala.ellipticcurve.RandomGenerator;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesOddCharacteristic;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesOddCharacteristic.AffinePoint;

public class KeyPairGenerator extends KeyPairGeneratorSpi implements Traceable {
  
  private SecureRandom secureRandom = new SecureRandom();
  private ECSchnorrSigGenParameterSpec ecSchnorrSigGenParameterSpec = new ECSchnorrSigGenParameterSpec(CurveCompilation.NIST, "P-256", true);

  @Override
  public KeyPair generateKeyPair() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("KeyPair", this, "generateKeyPair()");

    try {
      tracer.out().printfIndentln("this.ecSchnorrSigGenParameterSpec = %s", this.ecSchnorrSigGenParameterSpec);
      
      CurveSpec curveSpec;
      switch (this.ecSchnorrSigGenParameterSpec.getCurveCompilation()) {
      case NIST:
        curveSpec = NIST.curves.get(this.ecSchnorrSigGenParameterSpec.getCurveId());
        break;
      case BRAINPOOL:
        curveSpec = BrainPool.curves.get(this.ecSchnorrSigGenParameterSpec.getCurveId());
        break;
      default:
        throw new InvalidParameterException("Unsupported curve compilation.");
      }
      
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
      
      String curveId = "P-" + keySize;
      if (!NIST.curves.containsKey(curveId))
        throw new InvalidParameterException("Unsupported keysize: " + keySize + ".");
      
      this.ecSchnorrSigGenParameterSpec = new ECSchnorrSigGenParameterSpec(CurveCompilation.NIST, curveId, true);
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
      this.ecSchnorrSigGenParameterSpec = (ECSchnorrSigGenParameterSpec) algorithmParameterSpec;
      switch (this.ecSchnorrSigGenParameterSpec.getCurveCompilation()) {
      case NIST:
        if (!NIST.curves.containsKey(this.ecSchnorrSigGenParameterSpec.getCurveId()))
          throw new InvalidAlgorithmParameterException("Unknown curve: " + this.ecSchnorrSigGenParameterSpec.getCurveId());
        break;
      case BRAINPOOL:
        if (!BrainPool.curves.containsKey(this.ecSchnorrSigGenParameterSpec.getCurveId()))
          throw new InvalidAlgorithmParameterException("Unknown curve: " + this.ecSchnorrSigGenParameterSpec.getCurveId());
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
