# JCA-Provider (work in progress)

A provider for the Java Cryptography Architecture. Implementations are intended for the Schnorr Signature based on prime fields and elliptic curves
as well as for the Rabin-SAEP cryptosystem.

1. [Build](#Build)
2. [Installation](#Installation)
3. [Schnorr Signatures on prime fields](#PrimeFields)
  1. [KeyPairGenerator Usage](#PrimeFieldsKeyPair)
    1. [2048-bit prime p, 512-bit prime q](#PrimeFieldsKeyPair1)
    2. [1024-bit prime p, 160-bit prime q](#PrimeFieldsKeyPair2)
    3. [4096-bit prime p, 1024-bit prime q](#PrimeFieldsKeyPair3)
    4. [Custom security parameter](#PrimeFieldsKeyPair4)
  2. [Signature Usage](#PrimeFieldsSignature)
    1. [Simple Use](#PrimeFieldsSignature1)
    2. [Custom SecureRandom](#PrimeFieldsSignature2)
    3. [Nio](#PrimeFieldsSignature3)
    4. [Message Digest configuration](#PrimeFieldsSignature4)
    5. [Deterministic nonce](#PrimeFieldsSignature5)
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

The jca-bundle sub-module builds an uber-jar with the relevant binaries.

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

### <a name="PrimeFieldsKeyPair"></a>3.i KeyPairGenerator Usage

Key pairs can be generated by using precomputed Schnorr groups. This library provides Schnorr groups in different categories suitable for different security demands.
Schnorr groups with a 2048-bit prime p and a 512-bit prime q are preset. 

#### <a name="PrimeFieldsKeyPair1"></a>3.i.a 2048-bit prime p, 512-bit prime q

The subsequent example works with one of the precomputed Schnorr groups that are exhibiting default security parameters. It follows that, as mentioned above, 
p has 2048 bits and q has 512 bits. The `KeyPairGenerator` instance will select one of these groups at random.

```java
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import de.christofreichardt.crypto.schnorrsignature.SchnorrPublicKey;
...
KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SchnorrSignature");
KeyPair keyPair = keyPairGenerator.generateKeyPair();
SchnorrPublicKey publicKey = (SchnorrPublicKey) keyPair.getPublic();
assert publicKey.getSchnorrParams().getQ().bitLength() == 512;
assert publicKey.getSchnorrParams().getP().bitLength() == 2048;
```

#### <a name="PrimeFieldsKeyPair2"></a>3.i.b 1024-bit prime p, 160-bit prime q

Additionally, this library provides some precomputed Schnorr groups exhibiting minimal security parameters (1024-bit prime p, 160-bit prime q). 
This corresponds to the minimal parameter sizes of the Digital Signature Algorithm (DSA) as specified by the National Institute of Standards and Technology (NIST), 
see [FIPS PUB 186-4](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf) for more details. Such a group can be requested with the following code:

```java
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import de.christofreichardt.crypto.schnorrsignature.SchnorrPublicKey;
import de.christofreichardt.crypto.schnorrsignature.SchnorrSigKeyGenParameterSpec;
import de.christofreichardt.crypto.schnorrsignature.SchnorrSigKeyGenParameterSpec.Strength;
...
KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SchnorrSignature");
SchnorrSigKeyGenParameterSpec schnorrSigGenParameterSpec = new SchnorrSigKeyGenParameterSpec(Strength.MINIMAL);
keyPairGenerator.initialize(schnorrSigGenParameterSpec);
KeyPair keyPair = keyPairGenerator.generateKeyPair();
SchnorrPublicKey publicKey = (SchnorrPublicKey) keyPair.getPublic();
assert publicKey.getSchnorrParams().getQ().bitLength() == 160;
assert publicKey.getSchnorrParams().getP().bitLength() == 1024;
```

#### <a name="PrimeFieldsKeyPair3"></a>3.i.c 4096-bit prime p, 1024-bit prime q

Even some groups with a 4096-bit prime p and a 1024-bit prime q can be fetched from the precomputed pool:

```java
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import de.christofreichardt.crypto.schnorrsignature.SchnorrPublicKey;
import de.christofreichardt.crypto.schnorrsignature.SchnorrSigKeyGenParameterSpec;
import de.christofreichardt.crypto.schnorrsignature.SchnorrSigKeyGenParameterSpec.Strength;
...
KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SchnorrSignature");
SchnorrSigKeyGenParameterSpec schnorrSigGenParameterSpec = new SchnorrSigKeyGenParameterSpec(Strength.STRONG);
keyPairGenerator.initialize(schnorrSigGenParameterSpec);
KeyPair keyPair = keyPairGenerator.generateKeyPair();
SchnorrPublicKey publicKey = (SchnorrPublicKey) keyPair.getPublic();
assert publicKey.getSchnorrParams().getQ().bitLength() == 1024;
assert publicKey.getSchnorrParams().getP().bitLength() == 4096;
```

#### <a name="PrimeFieldsKeyPair4"></a>3.i.d Custom security parameter

If desired the `KeyPairGenerator` instance will compute a Schnorr group with custom security parameters from scratch.
The subsequent code will try to generate a Schnorr group with a 1024-bit prime p and a 256-bit prime q. 
That is to say q will have 256 bit exactly but p may have some bits less than 1024. If the specified parameter should be
matched exactly the last (boolean) parameter must be set to `true`.
Dependent on the chosen security limits this computation may take some time.

```java
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import de.christofreichardt.crypto.schnorrsignature.SchnorrPublicKey;
import de.christofreichardt.crypto.schnorrsignature.SchnorrSigKeyGenParameterSpec;
...
KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SchnorrSignature");
SchnorrSigKeyGenParameterSpec schnorrSigGenParameterSpec = new SchnorrSigKeyGenParameterSpec(1024, 256, false);
keyPairGenerator.initialize(schnorrSigGenParameterSpec);
KeyPair keyPair = keyPairGenerator.generateKeyPair();
SchnorrPublicKey publicKey = (SchnorrPublicKey) keyPair.getPublic();
assert publicKey.getSchnorrParams().getQ().bitLength() == 256;
```

### <a name="PrimeFieldsSignature"></a>3.i Signature Usage

Once you have generated a key pair, you can request a Signature instance either for the creation of a digital signature or
for its verification.

#### <a name="PrimeFieldsSignature1"></a>3.i.a Simple use

The subsequent example will use the default hash function (SHA-256). The nonce r needed for the computation of the digital signature
will be generated by an internal `SecureRandom` instance which will seed itself upon the first request of random bytes. Hence if
you sign the same document twice, both digital signature differ with high probability.

```java
import java.io.File;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.Signature;
...
KeyPair keyPair = ...
File file = new File("loremipsum.txt");
byte[] bytes = Files.readAllBytes(file.toPath());
Signature signature = Signature.getInstance("SchnorrSignature");
signature.initSign(keyPair.getPrivate());
signature.update(bytes);
byte[] signatureBytes = signature.sign();
signature.initVerify(keyPair.getPublic());
signature.update(bytes);
boolean verified = signature.verify(signatureBytes);
assert verified;
```

#### <a name="PrimeFieldsSignature2"></a>3.i.b Custom `SecureRandom`

It is essential that the nonce r is both unpredictable and unique as well as remains confidential. Note, that a single revealed r together with the corresponding
signature (e,y) suffices to compute the secret private key x, simply by solving the linear congruence 

<p align="center">y &#x2261;<sub>q</sub> r + ex</p>

If, on the other hand, the same r is used twice for two different documents, an adversary may obtain the private key by solving a system of linear congruences
with two unknowns:

<p align="center">y<sub>1</sub> &#x2261;<sub>q</sub> r + e<sub>1</sub>x</p>
<p align="center">y<sub>2</sub> &#x2261;<sub>q</sub> r + e<sub>2</sub>x</p>

Similar considerations also apply to the Digital Signature Algorithm (DSA) specified by the NIST.

Since the default `SecureRandom` instance may obtain random numbers from the underlying OS, weaknesses of the native random number generator (RNG) will be reflected by the signature.
Thus, someone might want to use a custom `SecureRandom` for the generation of the nonces. The subsequent example uses the SHA1PRNG which produces pseudo random numbers.
These pseudo random numbers will be computed deterministically but are hard to predict without knowledge of the seed.

```java
import java.io.File;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Signature;
...
KeyPair keyPair = ...
File file = new File("loremipsum.txt");
byte[] bytes = Files.readAllBytes(file.toPath());
SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
Signature signature = Signature.getInstance("SchnorrSignature");
signature.initSign(keyPair.getPrivate(), secureRandom);
signature.update(bytes);
byte[] signatureBytes = signature.sign();
signature.initVerify(keyPair.getPublic());
signature.update(bytes);
boolean verified = signature.verify(signatureBytes);
assert verified;
```

See also 3.1.d [Deterministic nonce](#PrimeFieldsSignature5).

#### <a name="PrimeFieldsSignature3"></a>3.i.b Nio

Suppose that you want digitally sign potentially large database dumps before archiving, thus ensuring data authenticity. The above shown approach wouldn't work well
since the method `byte[] readAllBytes(Path path)` is not intended for reading in large files. One way to process large files like database dumps is to use
NIO, see the next example:

```java
import java.io.File;
import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Signature;
...
KeyPair keyPair = ...
File largeDump = new File("dumped.sql");
byte[] bytes = Files.readAllBytes(largeDump.toPath());
Signature signature = Signature.getInstance("SchnorrSignature");
signature.initSign(keyPair.getPrivate());
int bufferSize = 512;
ByteBuffer buffer = ByteBuffer.allocate(bufferSize);
byte[] bytes = new byte[bufferSize];
try (FileInputStream fileInputStream = new FileInputStream(file)) {
  FileChannel fileChannel = fileInputStream.getChannel();
  do {
    int read = fileChannel.read(buffer);
    if (read == -1)
      break;
    buffer.flip();
    buffer.get(bytes, 0, read);
    signature.update(bytes, 0, read);
    buffer.clear();
  } while(true);
}
byte[] signatureBytes = signature.sign();
...
```

The verification process is similar. The `Signature` instance must be initialized for verifying and thereupon the byte chunks must be processed.
Finally, call the `boolean verify(byte[] signature)` method.

#### <a name="PrimeFieldsSignature4"></a>3.i.c Message Digest configuration

Denoting the output length of the cryptographic hash function with t, this turns the signature
<p align="center">(e,y) &#x220A; &#x2124;<sub>q</sub> &#x00D7; &#x2124;<sub>q</sub></p>
essentially into 
<p align="center">(e,y) &#x220A; &#x2124;<sub>2<sup>t</sup></sub> &#x00D7; &#x2124;<sub>q</sub></p>
Hence, assuming a 512-bit q, the preset SHA-256 is mapping only onto a very small subset of the domain &#x2124;<sub>q</sub>. However, this seems not to be a problem. 
Neven et al. argue within their paper, see [Hash Function Requirements for Schnorr Signatures](http://www.neven.org/papers/schnorr.pdf), that 
<p align="center">t = &#x2308;log<sub>2</sub> q&#x2309;/2</p>
should be sufficient to provide a security level of t bits. Hence SHA-256 is a natural choice for a 512-bit sized q (which is the default). A 1024-bit sized q however would require a
cryptographic hash function with 512 bit output length, e.g. SHA-512, to provide a security level of 512 bits. 

The to be used hash function can be configured by setting a property of the JCA provider. The subsequent code snippet configures SHA-512:

```java
Provider provider = new de.christofreichardt.crypto.Provider();
provider.put("de.christofreichardt.crypto.schnorrsignature.messageDigest", "SHA-512");
Security.addProvider(provider);
```

This requires, that another installed JCA provider supplies this message digest algorithm. This is true for the SUN provider coming with the official Oracle JDK.
Another popular JCA provider is [The Legion of the Bouncy Castle](https://www.bouncycastle.org/java.html). Installing this provider as well someone can use
the Schnorr Signature e.g. together with the Skein-1024 message digest. Skein has been one of finalists of the SHA-3 competition and has an output length of 1024 bits. 

#### <a name="PrimeFieldsSignature5"></a>3.i.d Deterministic nonce

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


