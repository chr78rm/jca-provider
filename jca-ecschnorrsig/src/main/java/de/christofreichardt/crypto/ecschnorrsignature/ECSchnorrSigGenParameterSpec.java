package de.christofreichardt.crypto.ecschnorrsignature;

import java.security.spec.AlgorithmParameterSpec;

public class ECSchnorrSigGenParameterSpec implements AlgorithmParameterSpec {
  public enum CurveCompilation {NIST, BRAINPOOL};
  
  final private CurveCompilation curveCompilation;
  final private String curveId;
  final private boolean useRandomBasePoint;
  
  public ECSchnorrSigGenParameterSpec(CurveCompilation curveCompilation, String curveId, boolean useRandomBasePoint) {
    this.curveCompilation = curveCompilation;
    this.curveId = curveId;
    this.useRandomBasePoint = useRandomBasePoint;
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

  @Override
  public String toString() {
    return "ECSchnorrSigGenParameterSpec[curveCompilation=" + curveCompilation+", curveId=" + curveId + ", useRandomBasePoint=" + useRandomBasePoint + "]";
  }

}
