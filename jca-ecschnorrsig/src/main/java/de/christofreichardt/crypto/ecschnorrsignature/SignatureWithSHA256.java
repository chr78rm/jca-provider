package de.christofreichardt.crypto.ecschnorrsignature;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.util.Arrays;

import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import de.christofreichardt.scala.ellipticcurve.GroupLaw.Element;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesOddCharacteristic;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesOddCharacteristic.AffinePoint;

public class SignatureWithSHA256 extends SignatureSpi implements Traceable {
  static final public int DIGEST_LENGTH = 32;

  final private MessageDigest messageDigest;
  private SecureRandom secureRandom = new SecureRandom();
  private ECSchnorrPrivateKey ecSchnorrPrivateKey;
  private ECSchnorrPublicKey ecSchnorrPublicKey;
  private BigInteger r;
  private boolean initialisedForSigning;
  private boolean initialisedForVerification;

  
  public SignatureWithSHA256() throws NoSuchAlgorithmException {
    this.messageDigest = MessageDigest.getInstance("SHA-256");
  }

  @Override
  @SuppressWarnings("deprecation")
  protected Object engineGetParameter(String arg0) throws InvalidParameterException {
    throw new UnsupportedOperationException("Unsupported operation.");
  }

  @Override
  protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "engineInitSign(PrivateKey privateKey)");
    
    try {
      tracer.out().printfIndentln("privateKey = %s", privateKey);
      
      if (!(privateKey instanceof ECSchnorrPrivateKey))
        throw new InvalidKeyException("Need a ECSchnorrPrivateKey instance.");
      this.ecSchnorrPrivateKey = (ECSchnorrPrivateKey) privateKey;
      
      CurveSpec curveSpec = this.ecSchnorrPrivateKey.getEcSchnorrParams().getCurveSpec();
      do {
        this.r = new BigInteger(curveSpec.getOrder().bitLength()*2, this.secureRandom).mod(curveSpec.getOrder());
      } while (r.equals(BigInteger.ZERO));
      
      this.messageDigest.reset();
      
      this.initialisedForSigning = true;
      this.initialisedForVerification = false;
    }
    finally {
      tracer.wayout();
    }
  }

  @Override
  protected void engineInitSign(PrivateKey privateKey, SecureRandom secureRandom) throws InvalidKeyException {
    this.secureRandom = secureRandom;
    engineInitSign(privateKey);
  }

  @Override
  protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "engineInitVerify(PublicKey publicKey)");
    
    try {
      tracer.out().printfIndentln("publicKey = %s", publicKey);
      
      if (!(publicKey instanceof ECSchnorrPublicKey))
        throw new InvalidKeyException("Need a SchnorrPublicKey instance.");
      
      this.ecSchnorrPublicKey = (ECSchnorrPublicKey) publicKey;
      this.messageDigest.reset();
      this.initialisedForVerification = true;
      this.initialisedForSigning = false;
    }
    finally {
      tracer.wayout();
    }
  }

  @Override
  @SuppressWarnings("deprecation")
  protected void engineSetParameter(String arg0, Object arg1) throws InvalidParameterException {
    throw new UnsupportedOperationException("Unsupported operation.");
  }

  @Override
  protected byte[] engineSign() throws SignatureException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("byte[]", this, "engineSign()");
    
    try {
      concatForSigning();
      byte[] digestBytes = this.messageDigest.digest();
      
      assert digestBytes.length == DIGEST_LENGTH;
      
      BigInteger order = this.ecSchnorrPrivateKey.getEcSchnorrParams().getCurveSpec().getOrder();
      BigInteger x = this.ecSchnorrPrivateKey.getX();
      BigInteger e = new BigInteger(digestBytes).mod(order);
      BigInteger y = e.multiply(x).add(this.r);
      byte[] yBytes = y.toByteArray();
      
      tracer.out().printfIndentln("e(%d) = %d", e.bitLength(), e);
      tracer.out().printfIndentln("y(%d) = %d", y.bitLength(), y);
      tracer.out().printfIndentln("yBytes.length = %d", yBytes.length);
      
      byte[] signatureBytes = Arrays.copyOf(digestBytes, DIGEST_LENGTH + yBytes.length);
      System.arraycopy(yBytes, 0, signatureBytes, DIGEST_LENGTH, yBytes.length);
      
      return signatureBytes;
    }
    finally {
      tracer.wayout();
    }
  }
  
  
  private void concatForSigning() {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("void", this, "concatForSigning()");
    
    try {
      AffinePoint gPoint = this.ecSchnorrPrivateKey.getEcSchnorrParams().getgPoint();
      AffinePoint sPoint = AffineCoordinatesOddCharacteristic.elemToAffinePoint(gPoint.multiply(this.r));
      
      tracer.out().printfIndentln("sPoint = %s", sPoint);
      
      CurveSpec curveSpec = this.ecSchnorrPrivateKey.getEcSchnorrParams().getCurveSpec();
      int length = curveSpec.getCurve().p().toByteArray().length;
      
      assert sPoint.x().toByteArray().length <= length  &&  sPoint.y().toByteArray().length <= length;
      
      this.messageDigest.update(Arrays.copyOf(sPoint.x().toByteArray(), length));
      this.messageDigest.update(Arrays.copyOf(sPoint.y().toByteArray(), length));
    }
    finally {
      tracer.wayout();
    }
  }


  @Override
  protected void engineUpdate(byte input) throws SignatureException {
    if (!this.initialisedForSigning && !this.initialisedForVerification)
      throw new SignatureException("Signature scheme hasn't been initialized.");
    
    this.messageDigest.update(input);
  }

  @Override
  protected void engineUpdate(byte[] bytes, int offset, int length) throws SignatureException {
    if (!this.initialisedForSigning && !this.initialisedForVerification)
      throw new SignatureException("Signature scheme hasn't been initialized.");
    
    this.messageDigest.update(bytes, offset, length);
  }

  @Override
  protected boolean engineVerify(byte[] signatureBytes) throws SignatureException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("boolean", this, "engineVerify(byte[] signatureBytes)");
    
    try {
      if (!this.initialisedForVerification)
        throw new SignatureException("Signature scheme hasn't been initialized for verification.");
      
      tracer.out().printIndentString();
      tracer.out().printf("signatureBytes(%d) = ", signatureBytes.length);
      traceBytes(signatureBytes);
      tracer.out().println();
      
      CurveSpec curveSpec = this.ecSchnorrPublicKey.getEcSchnorrParams().getCurveSpec();
      BigInteger e = concatForVerifying(signatureBytes);
      byte[] digestBytes = this.messageDigest.digest();
      
      return new BigInteger(digestBytes).mod(curveSpec.getOrder()).equals(e);
    }
    finally {
      tracer.wayout();
    }
  }
  
  private BigInteger concatForVerifying(byte[] signatureBytes) {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("BigInteger", this, "concatForVerifying(byte[] signatureBytes)");
    
    try {
      CurveSpec curveSpec = this.ecSchnorrPublicKey.getEcSchnorrParams().getCurveSpec();
      
      byte[] eBytes = Arrays.copyOfRange(signatureBytes, 0, DIGEST_LENGTH);
      BigInteger e = new BigInteger(eBytes).mod(curveSpec.getOrder());
      byte[] yBytes = Arrays.copyOfRange(signatureBytes, DIGEST_LENGTH, signatureBytes.length);
      BigInteger y = new BigInteger(yBytes);

      AffinePoint gPoint = this.ecSchnorrPublicKey.getEcSchnorrParams().getgPoint();
      AffinePoint hPoint = this.ecSchnorrPublicKey.gethPoint();
      Element element = (gPoint.multiply(y)).add(hPoint.multiply(e.negate().mod(curveSpec.getOrder())));
      AffinePoint sPoint = AffineCoordinatesOddCharacteristic.elemToAffinePoint(element);
      
      tracer.out().printfIndentln("sPoint = %s", sPoint);
      
      int length = curveSpec.getCurve().p().toByteArray().length;
      assert sPoint.x().toByteArray().length <= length  &&  sPoint.y().toByteArray().length <= length;
      this.messageDigest.update(Arrays.copyOf(sPoint.x().toByteArray(), length));
      this.messageDigest.update(Arrays.copyOf(sPoint.y().toByteArray(), length));
      
      return e;
    }
    finally {
      tracer.wayout();
    }
  }
  
  private void traceBytes(byte[] bytes) {
    AbstractTracer tracer = getCurrentTracer();
    for (byte signatureByte : bytes) {
      tracer.out().print(signatureByte & 255);
      tracer.out().print(' ');
    }
  }

  @Override
  public AbstractTracer getCurrentTracer() {
    return TracerFactory.getInstance().getCurrentPoolTracer();
  }

}
