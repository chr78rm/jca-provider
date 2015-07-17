package de.christofreichardt.crypto.ecschnorrsignature;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import scala.math.BigInt;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesWithPrimeField.AffineCurve;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesWithPrimeField.PrimeField;
import de.christofreichardt.scala.ellipticcurve.affine.ShortWeierstrass;
import de.christofreichardt.scala.ellipticcurve.affine.ShortWeierstrass.OddCharCoefficients;

public class BrainPool {
  static public final Map<String, CurveSpec> curves = new HashMap<>();
  static public final String[] curveIds = {"brainpoolP160r1", "brainpoolP160t1", "brainpoolP192r1", "brainpoolP192t1", "brainpoolP224r1", "brainpoolP224t1",
    "brainpoolP256r1", "brainpoolP256t1", "brainpoolP320r1", "brainpoolP320t1", "brainpoolP384r1", "brainpoolP384t1", "brainpoolP512r1",
    "brainpoolP512t1"};
  static {
//    String[] ids = {"brainpoolP160r1", "brainpoolP160t1", "brainpoolP192r1", "brainpoolP192t1", "brainpoolP224r1", "brainpoolP224t1",
//        "brainpoolP256r1", "brainpoolP256t1", "brainpoolP320r1", "brainpoolP320t1", "brainpoolP384r1", "brainpoolP384t1", "brainpoolP512r1",
//        "brainpoolP512t1"};
    BigInteger[] orders = { 
        new BigInteger("E95E4A5F737059DC60DF5991D45029409E60FC09", 16),
        new BigInteger("E95E4A5F737059DC60DF5991D45029409E60FC09", 16),
        new BigInteger("C302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1", 16),
        new BigInteger("C302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1", 16),
        new BigInteger("D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F", 16),
        new BigInteger("D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F", 16),
        new BigInteger("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7", 16),
        new BigInteger("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7", 16),
        new BigInteger("D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311", 16),
        new BigInteger("D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311", 16),
        new BigInteger("8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565", 16),
        new BigInteger("8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565", 16),
        new BigInteger("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069", 16),
        new BigInteger("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069", 16)
        };
    BigInteger[] p = {
        new BigInteger("E95E4A5F737059DC60DFC7AD95B3D8139515620F", 16),
        new BigInteger("E95E4A5F737059DC60DFC7AD95B3D8139515620F", 16),
        new BigInteger("C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297", 16),
        new BigInteger("C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297", 16),
        new BigInteger("D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF", 16),
        new BigInteger("D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF", 16),
        new BigInteger("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377", 16),
        new BigInteger("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377", 16),
        new BigInteger("D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27", 16),
        new BigInteger("D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27", 16),
        new BigInteger("8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53", 16),
        new BigInteger("8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53", 16),
        new BigInteger("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3", 16),
        new BigInteger("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3", 16),
        };
    BigInteger[] a = {
        new BigInteger("340E7BE2A280EB74E2BE61BADA745D97E8F7C300", 16),
        new BigInteger("E95E4A5F737059DC60DFC7AD95B3D8139515620C", 16),
        new BigInteger("6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EF", 16),
        new BigInteger("C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86294", 16),
        new BigInteger("68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43", 16),
        new BigInteger("D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FC", 16),
        new BigInteger("7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9", 16),
        new BigInteger("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5374", 16),
        new BigInteger("3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4", 16),
        new BigInteger("D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E24", 16),
        new BigInteger("7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826", 16),
        new BigInteger("8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC50", 16),
        new BigInteger("7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA", 16),
        new BigInteger("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F0", 16),
        };
    BigInteger[] b = {
        new BigInteger("1E589A8595423412134FAA2DBDEC95C8D8675E58", 16),
        new BigInteger("7A556B6DAE535B7B51ED2C4D7DAA7A0B5C55F380", 16),
        new BigInteger("469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9", 16),
        new BigInteger("13D56FFAEC78681E68F9DEB43B35BEC2FB68542E27897B79", 16),
        new BigInteger("2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B", 16),
        new BigInteger("4B337D934104CD7BEF271BF60CED1ED20DA14C08B3BB64F18A60888D", 16),
        new BigInteger("26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6", 16),
        new BigInteger("662C61C430D84EA4FE66A7733D0B76B7BF93EBC4AF2F49256AE58101FEE92B04", 16),
        new BigInteger("520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6", 16),
        new BigInteger("A7F561E038EB1ED560B3D147DB782013064C19F27ED27C6780AAF77FB8A547CEB5B4FEF422340353", 16),
        new BigInteger("04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11", 16),
        new BigInteger("7F519EADA7BDA81BD826DBA647910F8C4B9346ED8CCDC64E4B1ABD11756DCE1D2074AA263B88805CED70355A33B471EE", 16),
        new BigInteger("3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723", 16),
        new BigInteger("7CBBBCF9441CFAB76E1890E46884EAE321F70C0BCB4981527897504BEC3E36A62BCDFA2304976540F6450085F2DAE145C22553B465763689180EA2571867423E", 16),
        };
    for (int i=0; i<curveIds.length; i++) {
      OddCharCoefficients coefficients = new OddCharCoefficients(new BigInt(a[i]), new BigInt(b[i]));
      PrimeField primeField = ShortWeierstrass.makePrimeField(new BigInt(p[i]));
      AffineCurve curve = ShortWeierstrass.makeCurve(coefficients, primeField);
      CurveSpec curveSpec = new CurveSpec(curve, orders[i], BigInteger.ONE);
      curves.put(curveIds[i], curveSpec);
    }
  }
}
