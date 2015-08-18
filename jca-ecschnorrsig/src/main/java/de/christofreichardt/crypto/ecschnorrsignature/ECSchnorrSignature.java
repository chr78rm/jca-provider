package de.christofreichardt.crypto.ecschnorrsignature;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import de.christofreichardt.crypto.BigIntegerPair;
import de.christofreichardt.diagnosis.AbstractTracer;
import de.christofreichardt.diagnosis.LogLevel;
import de.christofreichardt.diagnosis.Traceable;
import de.christofreichardt.diagnosis.TracerFactory;
import de.christofreichardt.scala.ellipticcurve.GroupLaw.Element;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesWithPrimeField.AffinePoint;
import de.christofreichardt.scala.ellipticcurve.affine.ShortWeierstrass;

public class ECSchnorrSignature extends SignatureSpi implements Traceable {

  final private MessageDigest messageDigest;
  private SecureRandom secureRandom = new SecureRandom();
  private ECSchnorrPrivateKey ecSchnorrPrivateKey;
  private ECSchnorrPublicKey ecSchnorrPublicKey;
  private boolean initialisedForSigning;
  private boolean initialisedForVerification;
  private ECSchnorrSigParameterSpec ecSchnorrSigParameterSpec = new ECSchnorrSigParameterSpec();
  
  public ECSchnorrSignature() throws NoSuchAlgorithmException {
    this.messageDigest = digestInstance();
  }
  
  private MessageDigest digestInstance() throws NoSuchAlgorithmException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("MessageDigest", this, "digestInstance()");
    
    try {
      Provider provider = Security.getProvider(de.christofreichardt.crypto.Provider.NAME);
      String algorithmName;
      if (provider != null)
        algorithmName = provider.getProperty("de.christofreichardt.crypto.ecschnorrsignature.messageDigest", "SHA-256");
      else
        algorithmName = "SHA-256";
      
      tracer.out().printfIndentln("algorithmName = %s", algorithmName);
      
      return MessageDigest.getInstance(algorithmName);
    }
    finally {
      tracer.wayout();
    }
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
      resetForSigning();
    }
    finally {
      tracer.wayout();
    }
  }
  
  private void resetForSigning() {
    this.messageDigest.reset();
    this.ecSchnorrSigParameterSpec.getNonceGenerator().reset(this.secureRandom, 
        this.ecSchnorrPrivateKey.getEcSchnorrParams().getCurveSpec().getOrder(), this.ecSchnorrPrivateKey.getExtKeyBytes());
    this.initialisedForSigning = true;
    this.initialisedForVerification = false;
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
      resetForVerifying();
    }
    finally {
      tracer.wayout();
    }
  }
  
  private void resetForVerifying() {
    this.messageDigest.reset();
    this.initialisedForVerification = true;
    this.initialisedForSigning = false;
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
      try {
        BigInteger order = this.ecSchnorrPrivateKey.getEcSchnorrParams().getCurveSpec().getOrder();
        BigInteger x = this.ecSchnorrPrivateKey.getX();
        
        tracer.out().printfIndentln("order(%d) = %d", order.bitLength(), order);
        
        this.ecSchnorrSigParameterSpec.getNonceGenerator().copy(this.messageDigest);
        BigInteger e, r, y;
        byte[] digestBytes;
        do {
          do {
            r = this.ecSchnorrSigParameterSpec.getNonceGenerator().nonce();
          } while (r.equals(BigInteger.ZERO));
          
          digestBytes = concatForSigning(r);
          e = new BigInteger(1, digestBytes).mod(order);
          y = e.multiply(x).add(r).mod(order);
        } while(e.equals(BigInteger.ZERO) || y.equals(BigInteger.ZERO));
        
        tracer.out().printfIndentln("e(%d) = %d", e.bitLength(), e);
        tracer.out().printfIndentln("y(%d) = %d", y.bitLength(), y);
        
        BigIntegerPair pair = new BigIntegerPair(e, y);
        pair.trace();
        
        return pair.toByteArray();
      }
      finally {
        resetForSigning();
      }
    }
    finally {
      tracer.wayout();
    }
  }
  
  
  private byte[] concatForSigning(BigInteger r) throws SignatureException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("byte[]", this, "concatForSigning(BigInteger r)");
    
    try {
      AffinePoint gPoint = this.ecSchnorrPrivateKey.getEcSchnorrParams().getgPoint();
      Element element;
      switch (this.ecSchnorrSigParameterSpec.getPointMultiplicationStrategy()) {
      case FIXED_POINT:
        element = gPoint.fixedMultiply(r);
        break;
      case UNKNOWN_POINT:
        element = gPoint.multiply(r);
        break;
      default:
        throw new SignatureException("Unknown point multiplication strategy.");
      }
      AffinePoint sPoint = ShortWeierstrass.elemToAffinePoint(element);
      
      tracer.out().printfIndentln("sPoint = %s", sPoint);
      
      try {
        MessageDigest messageDigest = (MessageDigest) this.messageDigest.clone();
        CurveSpec curveSpec = this.ecSchnorrPrivateKey.getEcSchnorrParams().getCurveSpec();
        int length = curveSpec.getCurve().p().toByteArray().length;
        assert sPoint.x().toByteArray().length <= length  &&  sPoint.y().toByteArray().length <= length;
        messageDigest.update(Arrays.copyOf(sPoint.x().toByteArray(), length));
        messageDigest.update(Arrays.copyOf(sPoint.y().toByteArray(), length));
        
        return messageDigest.digest();
      }
      catch (CloneNotSupportedException ex) {
        tracer.logException(LogLevel.ERROR, ex, getClass(), "byte[] concatForSigning(BigInteger r)");
        throw new SignatureException(ex);
      }
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
    this.ecSchnorrSigParameterSpec.getNonceGenerator().update(input);
  }

  @Override
  protected void engineUpdate(byte[] bytes, int offset, int length) throws SignatureException {
    if (!this.initialisedForSigning && !this.initialisedForVerification)
      throw new SignatureException("Signature scheme hasn't been initialized.");
    
    this.messageDigest.update(bytes, offset, length);
    this.ecSchnorrSigParameterSpec.getNonceGenerator().update(bytes, offset, length);
  }

  @Override
  protected boolean engineVerify(byte[] signatureBytes) throws SignatureException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("boolean", this, "engineVerify(byte[] signatureBytes)");
    
    try {
      try {
        if (!this.initialisedForVerification)
          throw new SignatureException("Signature scheme hasn't been initialized for verification.");
        
        CurveSpec curveSpec = this.ecSchnorrPublicKey.getEcSchnorrParams().getCurveSpec();
        BigInteger e = concatForVerifying(signatureBytes);
        byte[] digestBytes = this.messageDigest.digest();
        
        return e != null  &&  new BigInteger(1, digestBytes).mod(curveSpec.getOrder()).equals(e);
      }
      finally {
        resetForVerifying();
      }
    }
    finally {
      tracer.wayout();
    }
  }
  
  private BigInteger concatForVerifying(byte[] signatureBytes) throws SignatureException {
    AbstractTracer tracer = getCurrentTracer();
    tracer.entry("BigInteger", this, "concatForVerifying(byte[] signatureBytes)");
    
    try {
      CurveSpec curveSpec = this.ecSchnorrPublicKey.getEcSchnorrParams().getCurveSpec();
      
      BigIntegerPair pair = new BigIntegerPair(signatureBytes);
      pair.trace();
      BigInteger e = pair.getE();
      BigInteger y = pair.getY();
      
      if (e.compareTo(curveSpec.getOrder()) == -1  &&  y.compareTo(curveSpec.getOrder()) == -1) {
        AffinePoint gPoint = this.ecSchnorrPublicKey.getEcSchnorrParams().getgPoint();
        AffinePoint hPoint = this.ecSchnorrPublicKey.gethPoint();
        Element element;
        switch (this.ecSchnorrSigParameterSpec.getPointMultiplicationStrategy()) {
        case FIXED_POINT:
          element = (gPoint.fixedMultiply(y)).add(hPoint.fixedMultiply(e.negate().mod(curveSpec.getOrder())));
          break;
        case UNKNOWN_POINT:
          element = (gPoint.multiply(y)).add(hPoint.multiply(e.negate().mod(curveSpec.getOrder())));
          break;
        default:
          throw new SignatureException("Unknown point multiplication strategy.");
        }
        AffinePoint sPoint = ShortWeierstrass.elemToAffinePoint(element);
        
        tracer.out().printfIndentln("sPoint = %s", sPoint);
        
        int length = curveSpec.getCurve().p().toByteArray().length;
        assert sPoint.x().toByteArray().length <= length  &&  sPoint.y().toByteArray().length <= length;
        this.messageDigest.update(Arrays.copyOf(sPoint.x().toByteArray(), length));
        this.messageDigest.update(Arrays.copyOf(sPoint.y().toByteArray(), length));
      }
      else
        e = null;
      
      return e;
    }
    finally {
      tracer.wayout();
    }
  }
  
  @Override
  protected AlgorithmParameters engineGetParameters() {
    throw new UnsupportedOperationException("Unsupported operation.");
  }

  @Override
  protected void engineSetParameter(AlgorithmParameterSpec algorithmParameterSpec) throws InvalidAlgorithmParameterException {
    if (!(algorithmParameterSpec instanceof ECSchnorrSigParameterSpec))
      throw new InvalidAlgorithmParameterException("Need a 'ECSchnorrSigParameterSpec'.");
    
    this.ecSchnorrSigParameterSpec = (ECSchnorrSigParameterSpec) algorithmParameterSpec;
  }

  @Override
  public AbstractTracer getCurrentTracer() {
    return TracerFactory.getInstance().getCurrentPoolTracer();
  }

}
