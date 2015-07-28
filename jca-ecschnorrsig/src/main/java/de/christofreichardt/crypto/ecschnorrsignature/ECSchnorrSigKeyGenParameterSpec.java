package de.christofreichardt.crypto.ecschnorrsignature;

import java.security.spec.AlgorithmParameterSpec;

public class ECSchnorrSigKeyGenParameterSpec implements AlgorithmParameterSpec {
  public enum CurveCompilation {NIST, BRAINPOOL};
  
  final private CurveCompilation curveCompilation;
  final private String curveId;
  final private boolean useRandomBasePoint;
  
  public ECSchnorrSigKeyGenParameterSpec(CurveCompilation curveCompilation, String curveId, boolean useRandomBasePoint) {
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
    return "ECSchnorrSigKeyGenParameterSpec[curveCompilation=" + curveCompilation+", curveId=" + curveId + ", useRandomBasePoint=" + useRandomBasePoint + "]";
  }

}
