package de.christofreichardt.crypto.ecschnorrsignature;

import java.security.spec.AlgorithmParameterSpec;

public class ECSchnorrSigKeyGenParameterSpec implements AlgorithmParameterSpec {
  public enum CurveCompilation {NIST, BRAINPOOL, SAFECURVES, CUSTOM};
  
  final private CurveCompilation curveCompilation;
  final private String curveId;
  final private boolean useRandomBasePoint;
  private final boolean extended;
  final private CurveSpec curveSpec;
  
  public ECSchnorrSigKeyGenParameterSpec(CurveCompilation curveCompilation, String curveId) {
    this(curveCompilation, curveId, false);
  }

  public ECSchnorrSigKeyGenParameterSpec(CurveCompilation curveCompilation, String curveId, boolean useRandomBasePoint) {
    this(curveCompilation, curveId, useRandomBasePoint, false);
  }
  
  public ECSchnorrSigKeyGenParameterSpec(CurveCompilation curveCompilation, String curveId, boolean useRandomBasePoint, boolean extended) {
    this.curveCompilation = curveCompilation;
    this.curveId = curveId;
    this.useRandomBasePoint = useRandomBasePoint;
    this.extended = extended;
    this.curveSpec = null;
  }
  
  public ECSchnorrSigKeyGenParameterSpec(CurveSpec curveSpec) {
    this(curveSpec, false);
  }
  
  public ECSchnorrSigKeyGenParameterSpec(CurveSpec curveSpec, boolean useRandomBasePoint) {
    this(curveSpec, useRandomBasePoint, false);
  }
  
  public ECSchnorrSigKeyGenParameterSpec(CurveSpec curveSpec, boolean useRandomBasePoint, boolean extended) {
    this.curveCompilation = CurveCompilation.CUSTOM;
    this.curveId = null;
    this.useRandomBasePoint = useRandomBasePoint;
    this.extended = extended;
    this.curveSpec = curveSpec;
  }

  public CurveCompilation getCurveCompilation() {
    return curveCompilation;
  }

  public String getCurveId() {
    return curveId;
  }

  public boolean isUseRandomBasePoint() {
    return useRandomBasePoint;
  }

  public boolean isExtended() {
    return extended;
  }

  public CurveSpec getCurveSpec() {
    return curveSpec;
  }

  @Override
  public String toString() {
    return "ECSchnorrSigKeyGenParameterSpec[curveCompilation=" + this.curveCompilation+", curveId=" + this.curveId + ", useRandomBasePoint=" + this.useRandomBasePoint + ", extended=" + this.extended + "]";
  }

}
