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

public class KeyPairGenerator extends KeyPairGeneratorSpi implements Traceable {
  final public static int EXT_KEYBYTES = 16;
  
  private SecureRandom secureRandom = new SecureRandom();
  private ECSchnorrSigKeyGenParameterSpec ecSchnorrSigKeyGenParameterSpec = new ECSchnorrSigKeyGenParameterSpec(CurveCompilation.BRAINPOOL, "brainpoolP256r1", false);

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
      case SAFECURVES:
        curveSpec = SafeCurves.curves.get(this.ecSchnorrSigKeyGenParameterSpec.getCurveId());
        break;
      case CUSTOM:
        curveSpec = this.ecSchnorrSigKeyGenParameterSpec.getCurveSpec();
        break;
      default:
        throw new InvalidParameterException("Unsupported curve compilation.");
      }
      
      AffinePoint gPoint;
      if (this.ecSchnorrSigKeyGenParameterSpec.isUseRandomBasePoint()) {
        do {
          AffinePoint randomPoint = curveSpec.getCurve().randomPoint(new RandomGenerator(this.secureRandom));
          Element element = randomPoint.multiply(curveSpec.getCoFactor());
          if (!element.isNeutralElement() && element.multiply(curveSpec.getOrder()).isNeutralElement()) {
            gPoint = (AffinePoint) element.toPoint();
            break;
          }
        } while (true);
      }
      else
        gPoint = curveSpec.getgPoint();
      
      assert gPoint.multiply(curveSpec.getOrder()).isNeutralElement();
      
      BigInteger x;
      do {
        x = new BigInteger(curveSpec.getOrder().bitLength()*2, this.secureRandom).mod(curveSpec.getOrder());
      } while(x.equals(BigInteger.ZERO));
      
      Element element = gPoint.multiply(x);
      assert !element.isNeutralElement();
      AffinePoint hPoint = (AffinePoint) element.toPoint();
      
      tracer.out().printfIndentln("gPoint = %s", gPoint);
      tracer.out().printfIndentln("x = %s", x);
      tracer.out().printfIndentln("hPoint = %s", hPoint);
      
      ECSchnorrParams ecSchnorrParams = new ECSchnorrParams(curveSpec, gPoint);
      ECSchnorrPublicKey ecSchnorrPublicKey = new ECSchnorrPublicKey(ecSchnorrParams, hPoint);
      ECSchnorrPrivateKey ecSchnorrPrivateKey;
      if (this.ecSchnorrSigKeyGenParameterSpec.isExtended()) {
        byte[] extraKeyBytes = new byte[EXT_KEYBYTES];
        this.secureRandom.nextBytes(extraKeyBytes);
        ecSchnorrPrivateKey = new ECSchnorrPrivateKey(ecSchnorrParams, x, extraKeyBytes);
      }
      else 
        ecSchnorrPrivateKey = new ECSchnorrPrivateKey(ecSchnorrParams, x);
      
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
      
      String curveId = "brainpoolP" + keySize + "r1";
      if (!BrainPool.curves.containsKey(curveId))
        throw new InvalidParameterException("Unsupported keysize: " + keySize + ".");
      
      this.ecSchnorrSigKeyGenParameterSpec = new ECSchnorrSigKeyGenParameterSpec(CurveCompilation.BRAINPOOL, curveId, false);
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
      case SAFECURVES:
        if (!SafeCurves.curves.containsKey(this.ecSchnorrSigKeyGenParameterSpec.getCurveId()))
          throw new InvalidAlgorithmParameterException("Unknown curve: " + this.ecSchnorrSigKeyGenParameterSpec.getCurveId());
        break;
      case CUSTOM:
        if (this.ecSchnorrSigKeyGenParameterSpec.getCurveSpec() == null)
          throw new InvalidAlgorithmParameterException("Need a curve specification.");
        break;
      default:
        throw new InvalidAlgorithmParameterException("Unsupported curve compilation.");
      }
      this.secureRandom = secureRandom;
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
