# JCA-Provider

A provider for the Java Cryptography Architecture. Implementations are intended for the Schnorr Signature based on prime fields and elliptic curves
as well as for the Rabin-SAEP cryptosystem.

1. [Build](#Build)
2. [Installation](#Installation)
3. [Schnorr Signatures on prime fields](#PrimeFields)
  1. [Usage](#PrimeFieldsUsage)
4. [Schnorr Signatures on elliptic curves](#EllipticCurves)
5. [Links](#Links)

## <a name="Build"></a>1. Build

[Maven](https://maven.apache.org/) is required to compile the library. A whole build will take some time - currently up to three minutes on my laptop. 
This is mainly due to the unit tests belonging to the jca-schnorrsig sub-module. The custom domain parameter generation includes the search 
for random [Schnorr Groups](https://en.wikipedia.org/wiki/Schnorr_group) satisfying specified security limits. 

The build will need a JDK 8 since I'm using the -Xdoclint:none option to turn off the new doclint. This option doesn't exist in pre Java 8.
Aside from that, the build targets JDK 7+.

`mvn clean install`

Experimental test cases concerning the group order of elliptic curves over prime fields may sometimes fail due to their probabilistic character. 
However this is rather unlikely and a repetition of the build will suffice in most cases.

## <a name="Installation"></a>2. Installation

Cryptographic Service Providers can be installed in two ways:
- on the normal Java classpath
- as a bundled extension

Furthermore, a Cryptographic Service Provider (CSP) must be registered before it can be put to use. CSPs can be registered statically by editing
a security properties configuration file or dynamically at runtime:

```java
Provider provider = new de.christofreichardt.crypto.Provider();
Security.addProvider(provider);
```

See the section [Installing Providers](http://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#ProviderInstalling) of
the official [JCA Reference Guide](http://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html) for more details.

## <a name="PrimeFields"></a>3. Schnorr Signatures on prime fields

<table summary="">
  <tbody>
    <tr>
      <td style="font-weight: bold">Public domain parameter</td>
      <td style="padding-left: 20px">g, G = &#x27E8;g&#x27E9;, |G| = q, p = qr + 1, p prime, q prime, H: {0,1}<sup>&#x002A;</sup> &#x2192; &#x2124;<sub>q</sub></td>
    </tr>
    <tr>
      <td style="font-weight: bold">Secret key</td>
      <td style="padding-left: 20px"> x &#x220A;<sub>R</sub> (&#x2124;<sub>q</sub>)<sup>&#x00D7;</sup></td>
    </tr>
    <tr>
      <td style="font-weight: bold">Public key</td>
      <td style="padding-left: 20px">h &#x2261;<sub>p</sub> g<sup>x</sup></td>
    </tr>
    <tr>
      <td style="font-weight: bold">Signing M&#x220A;{0,1}<sup>*</sup></td>
      <td style="padding-left: 20px">
        r &#x220A;<sub>R</sub> (&#x2124;<sub>q</sub>)<sup>&#x00D7;</sup>, s &#x2261;<sub>p</sub> g<sup>r</sup>,
        e &#x2261;<sub>q</sub> H(M &#x2016; s), y &#x2261;<sub>q</sub> r + ex
      </td>
    </tr>
    <tr>
      <td style="font-weight: bold">Signature</td>
      <td style="padding-left: 20px">(e,y) &#x220A; &#x2124;<sub>q</sub> &#x00D7; &#x2124;<sub>q</sub></td>
    </tr>
    <tr>
      <td style="font-weight: bold">Verifying</td>
      <td style="padding-left: 20px">
        s &#x2261;<sub>p</sub> g<sup>y</sup>h<sup>-e</sup>,
        check if H(M &#x2016; s) &#x2261;<sub>q</sub> e holds.
      </td>
    </tr>
    <tr>
      <td style="font-weight: bold">Correctness</td>
      <td style="padding-left: 20px">
        g<sup>y</sup>h<sup>-e</sup> &#x2261;<sub>p</sub> g<sup>y</sup>g<sup>-ex</sup> &#x2261;<sub>p</sub> g<sup>y-ex</sup> &#x2261;<sub>p</sub> g<sup>r</sup>
      </td>
    </tr>
  </tbody>
</table>

### <a name="PrimeFieldsUsage"></a>3.1 Usage

The subsequent example works with one of the precomputed Schnorr groups that are exhibiting default security parameters. This means p has 2048 bits and q has 512 bits.
The `KeyPairGenerator` instance will select one of these groups at random.

```java
File file = new File("loremipsum.txt");
byte[] bytes = Files.readAllBytes(file.toPath());
KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SchnorrSignature");
KeyPair keyPair = keyPairGenerator.generateKeyPair();
Signature signature = Signature.getInstance("SchnorrSignatureWithSHA256");
signature.initSign(keyPair.getPrivate());
signature.update(bytes);
byte[] signatureBytes = signature.sign();
signature.initVerify(keyPair.getPublic());
signature.update(bytes);
boolean verified = signature.verify(signatureBytes);
assert verified;
```

Additionally, this library provides some precomputed Schnorr groups exhibiting minimal security parameters (1024-bit prime p, 160-bit prime q). 
This corresponds to the minimal parameter sizes of the Digital Signature Algorithm (DSA) as specified by the National Institute of Standards and Technology (NIST), 
see [FIPS PUB 186-4](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf) for more details. Such a group can be requested with the following code:

```java
KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SchnorrSignature");
SchnorrSigKeyGenParameterSpec schnorrSigGenParameterSpec = new SchnorrSigKeyGenParameterSpec(Strength.MINIMAL);
keyPairGenerator.initialize(schnorrSigGenParameterSpec);
KeyPair keyPair = keyPairGenerator.generateKeyPair();
SchnorrPublicKey publicKey = (SchnorrPublicKey) keyPair.getPublic();
assert publicKey.getSchnorrParams().getQ().bitLength() == 160;
assert publicKey.getSchnorrParams().getP().bitLength() == 1024;
```

Even some groups with a 4096-bit prime p and a 1024-bit prime q can be fetched from the precomputed pool:

```java
KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SchnorrSignature");
SchnorrSigKeyGenParameterSpec schnorrSigGenParameterSpec = new SchnorrSigKeyGenParameterSpec(Strength.STRONG);
keyPairGenerator.initialize(schnorrSigGenParameterSpec);
KeyPair keyPair = keyPairGenerator.generateKeyPair();
SchnorrPublicKey publicKey = (SchnorrPublicKey) keyPair.getPublic();
assert publicKey.getSchnorrParams().getQ().bitLength() == 1024;
assert publicKey.getSchnorrParams().getP().bitLength() == 4096;
```

If desired the `KeyPairGenerator` instance will compute a Schnorr group with custom security parameters from scratch.
The subsequent code will try to generate a Schnorr group with a 1024-bit prime p and a 256-bit prime q. 
That is to say q will have 256 bit exactly but p may have some bits less than 1024. If the specified parameter should be
matched exactly the last (boolean) parameter must be set to `true`.
Dependent on the chosen security limits this computation may take some time.

```java
KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SchnorrSignature");
SchnorrSigKeyGenParameterSpec schnorrSigGenParameterSpec = new SchnorrSigKeyGenParameterSpec(1024, 256, false);
keyPairGenerator.initialize(schnorrSigGenParameterSpec);
KeyPair keyPair = keyPairGenerator.generateKeyPair();
SchnorrPublicKey publicKey = (SchnorrPublicKey) keyPair.getPublic();
assert publicKey.getSchnorrParams().getQ().bitLength() == 256;
```



## <a name="EllipticCurves"></a>4. Schnorr Signatures on elliptic curves

<table summary="">
  <tbody>
    <tr>
      <td style="font-weight: bold">Public domain parameter</td>
      <td style="padding-left: 20px">Elliptic curve E(&#x1D53D;<sub>p</sub>), p prime, #E(&#x1D53D;<sub>p</sub>)=n&#x22C5;d, n prime, d &lt;&lt; n</td>
    </tr>
    <tr>
      <td style="font-weight: bold"></td>
      <td style="padding-left: 20px">g &#x220A; E(&#x1D53D;<sub>p</sub>), order(g) = n &#x21D2; [n]&#x22C5;g &#x2261;<sub>E</sub> &#x1D4DE;, H: {0,1}<sup>&#x002A;</sup> &#x2192; &#x2124;<sub>n</sub></td>
    </tr>
    <tr>
      <td style="font-weight: bold">Secret key</td>
      <td style="padding-left: 20px"> x &#x220A;<sub>R</sub> (&#x2124;<sub>n</sub>)<sup>&#x00D7;</sup></td>
    </tr>
    <tr>
      <td style="font-weight: bold">Public key</td>
      <td style="padding-left: 20px">h &#x2261;<sub>E</sub> [x]&#x22C5;g</td>
    </tr>
    <tr>
      <td style="font-weight: bold">Signing M&#x220A;{0,1}<sup>*</sup></td>
      <td style="padding-left: 20px">
        r &#x220A;<sub>R</sub> (&#x2124;<sub>n</sub>)<sup>&#x00D7;</sup>, s &#x2261;<sub>E</sub> [r]&#x22C5;g,
        e &#x2261;<sub>n</sub> H(M &#x2016; s), y &#x2261;<sub>n</sub> r + ex
      </td>
    </tr>
    <tr>
      <td style="font-weight: bold">Signature</td>
      <td style="padding-left: 20px">(e,y) &#x220A; &#x2124;<sub>n</sub> &#x00D7; &#x2124;<sub>n</sub></td>
    </tr>
    <tr>
      <td style="font-weight: bold">Verifying</td>
      <td style="padding-left: 20px">s &#x2261;<sub>E</sub> [y]&#x22C5;g + [-e]&#x22C5;h, check if H(M &#x2016; s) &#x2261;<sub>n</sub> e holds.</td>
    </tr>
    <tr>
      <td style="font-weight: bold">Correctness</td>
      <td style="padding-left: 20px">[y]&#x22C5;g + [-e]&#x22C5;h &#x2261;<sub>E</sub> [y]&#x22C5;g + [-ex]&#x22C5;g &#x2261;<sub>E</sub> [y - ex]&#x22C5;g &#x2261;<sub>E</sub> [r]&#x22C5;g</td>
    </tr>
  </tbody>
</table>

## <a name="Links"></a>5. Links

- [Maven](https://maven.apache.org/)
- [Schnorr Groups](https://en.wikipedia.org/wiki/Schnorr_group)
- [JCA Reference Guide](http://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html)
- [FIPS PUB 186-4](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)


