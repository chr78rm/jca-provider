# JCA-Provider (work in progress)

A provider for the Java Cryptography Architecture. Implementations are intended for the Schnorr Signature based on prime fields and elliptic curves.

## <a name="TOC"></a>1. Table of Contents

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
    3. [NIO](#PrimeFieldsSignature3)
    4. [Message Digest configuration](#PrimeFieldsSignature4)
    5. [(Deterministic) NonceGenerators](#PrimeFieldsSignature5)
4. [Schnorr Signatures on elliptic curves](#EllipticCurves)
  1. [KeyPairGenerator Usage](#EllipticCurveKeyPair)
    1. [Brainpool Curves](#EllipticCurveKeyPair1)
    2. [NIST Curves](#EllipticCurveKeyPair2)
    3. [SafeCurves](#EllipticCurveKeyPair3)
    4. [Custom Curves](#EllipticCurveKeyPair4)
  2. [Signature Usage](#EllipticCurveSignature)
    1. [Simple Use](#EllipticCurveSignature1)
    2. [Custom SecureRandom](#EllipticCurveSignature2)
    3. [NIO](#EllipticCurveSignature3)
    4. [Message Digest configuration](#EllipticCurveSignature4)
    5. [(Deterministic) NonceGenerators](#EllipticCurveSignature5)
    6. [Point Multiplication methods](#EllipticCurveSignature6)
5. [Links](#Links)

## <a name="Build"></a>1. Build

[Maven](https://maven.apache.org/) is required to compile the library. A whole build will take some time - currently up to five minutes on my laptop. 
This is mainly due to the unit tests belonging to the jca-schnorrsig and jca-ecschnorrsig sub-modules. For example, the to be tested custom domain parameter generation includes the 
costly search for random [Schnorr Groups](https://en.wikipedia.org/wiki/Schnorr_group) satisfying specified security limits. 

The build will need a JDK 8 since I'm using the -Xdoclint:none option to turn off the new doclint. This option doesn't exist in pre Java 8.
Aside from that, the build targets JDK 7+. Use

`$ mvn clean install`

to build the library along with the unit tests. Instead, you might want execute

`$ mvn clean install -DskipTests`

to reduce the build time significantly.

[TOC](#TOC)

## <a name="Installation"></a>2. Installation

Cryptographic Service Providers can be installed in two ways:
- on the normal Java classpath
- as a bundled extension

The jca-bundle sub-module builds an uber-jar with the relevant binaries.

Furthermore, a Cryptographic Service Provider (CSP) must be registered before it can be put to use. CSPs can be registered statically by editing
a security properties configuration file or dynamically at runtime:

```java
import java.security.Provider;
import java.security.Security;
...
Provider provider = new de.christofreichardt.crypto.Provider();
Security.addProvider(provider);
```

See the section [Installing Providers](http://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#ProviderInstalling) of
the official [JCA Reference Guide](http://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html) for more details.

[TOC](#TOC)

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
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
...
KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SchnorrSignature");
KeyPair keyPair = keyPairGenerator.generateKeyPair();
SchnorrPublicKey publicKey = (SchnorrPublicKey) keyPair.getPublic();
BigInteger q = publicKey.getSchnorrParams().getQ();
BigInteger p = publicKey.getSchnorrParams().getP();
assert q.bitLength() == 512;
assert p.bitLength() == 2048;
assert q.isProbablePrime(100);
assert p.isProbablePrime(100);
assert p.subtract(BigInteger.ONE).remainder(q).equals(BigInteger.ZERO);
```

#### <a name="PrimeFieldsKeyPair2"></a>3.i.b 1024-bit prime p, 160-bit prime q

Additionally, this library provides some precomputed Schnorr groups exhibiting minimal security parameters (1024-bit prime p, 160-bit prime q). 
This corresponds to the minimal parameter sizes of the Digital Signature Algorithm (DSA) as specified by the National Institute of Standards and Technology (NIST), 
see [FIPS PUB 186-4](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf) for more details. Such a group can be requested with the following code:

```java
import java.math.BigInteger;
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
BigInteger q = publicKey.getSchnorrParams().getQ();
BigInteger p = publicKey.getSchnorrParams().getP();
assert q.bitLength() == 160;
assert p.bitLength() == 1024;
assert q.isProbablePrime(100);
assert p.isProbablePrime(100);
assert p.subtract(BigInteger.ONE).remainder(q).equals(BigInteger.ZERO);
```

#### <a name="PrimeFieldsKeyPair3"></a>3.i.c 4096-bit prime p, 1024-bit prime q

Even some groups with a 4096-bit prime p and a 1024-bit prime q can be fetched from the precomputed pool:

```java
import java.math.BigInteger;
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
BigInteger q = publicKey.getSchnorrParams().getQ();
BigInteger p = publicKey.getSchnorrParams().getP();
assert q.bitLength() == 1024;
assert p.bitLength() == 4096;
assert q.isProbablePrime(100);
assert p.isProbablePrime(100);
assert p.subtract(BigInteger.ONE).remainder(q).equals(BigInteger.ZERO);
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
BigInteger q = publicKey.getSchnorrParams().getQ();
BigInteger p = publicKey.getSchnorrParams().getP();
assert q.bitLength() == 256;
assert q.isProbablePrime(100);
assert p.isProbablePrime(100);
assert p.subtract(BigInteger.ONE).remainder(q).equals(BigInteger.ZERO);
```

### <a name="PrimeFieldsSignature"></a>3.ii Signature Usage

Once you have generated a key pair, you can request a Signature instance either for the creation of a digital signature or
for its verification.

#### <a name="PrimeFieldsSignature1"></a>3.ii.a Simple use

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

#### <a name="PrimeFieldsSignature2"></a>3.ii.b Custom `SecureRandom`

It is essential that the nonce r is both unpredictable and unique as well as remains confidential. Note, that a single revealed r together with the corresponding
signature (e,y) suffices to compute the secret private key x, simply by solving the linear congruence 

<p align="center">y &#x2261;<sub>q</sub> r + ex</p>

If, on the other hand, the same r is used twice for two different documents, an adversary may obtain the private key by solving a system of linear congruences
with two unknowns:

<p align="center">y<sub>1</sub> &#x2261;<sub>q</sub> r + e<sub>1</sub>x</p>
<p align="center">y<sub>2</sub> &#x2261;<sub>q</sub> r + e<sub>2</sub>x</p>

Similar considerations also apply to the Digital Signature Algorithm (DSA) specified by the NIST.

Since the default `SecureRandom` instance may obtain random numbers from the underlying OS, weaknesses of the native Random Number Generator (RNG) will be reflected by the signature.
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

See also 3.1.d [(Deterministic) NonceGenerators](#PrimeFieldsSignature5).

#### <a name="PrimeFieldsSignature3"></a>3.ii.c NIO

Suppose that you want digitally sign potentially large database dumps before archiving, thus ensuring data authenticity. The above shown approach wouldn't work well
since the method `byte[] readAllBytes(Path path)` is not intended for reading in large files. One way to process large files like database dumps is to use
NIO, see the next example:

```java
import java.io.File;
import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Signature;
...
KeyPair keyPair = ...
File largeDump = new File("dumped.sql");
Signature signature = Signature.getInstance("SchnorrSignature");
signature.initSign(keyPair.getPrivate());
int bufferSize = 512;
ByteBuffer buffer = ByteBuffer.allocate(bufferSize);
byte[] bytes = new byte[bufferSize];
try (FileInputStream fileInputStream = new FileInputStream(largeDump)) {
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

#### <a name="PrimeFieldsSignature4"></a>3.ii.d Message Digest configuration

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
import java.security.Provider;
import java.security.Security;
...
Provider provider = new de.christofreichardt.crypto.Provider();
provider.put("de.christofreichardt.crypto.schnorrsignature.messageDigest", "SHA-512");
Security.addProvider(provider);
```

This requires, that another installed JCA provider supplies this message digest algorithm. This is true for the SUN provider coming with the official Oracle JDK.
Another popular JCA provider is [The Legion of the Bouncy Castle](https://www.bouncycastle.org/java.html). Installing this provider as well someone can use
the Schnorr Signature e.g. together with the Skein-1024 message digest. Skein has been one of finalists of the SHA-3 competition and has an output length of 1024 bits. 

#### <a name="PrimeFieldsSignature5"></a>3.ii.e (Deterministic) NonceGenerators

As mentioned in section [3.i.b](#PrimeFieldsSignature2), custom `SecureRandom` implementations can be injected into the `Signature` engine. Such implementations
may use True Random Number Generators (TRNG) under the hood. Unfortunately, the efficiency of TRNGs is rather poor. Hence TRNGs might not produce enough random numbers in time
for the desired throughput. As a consequence of their slowness TRNGs are often only used to (re)seed Pseudo Random Number Generators (PRNG) like SHA1PRNG coming with the SUN JCA provider.

In general, someone need not to be concerned about duplicate nonces so long as the employed algorithms and the RNG in use produces an (almost) uniform distribution over &#x2124;<sub>q</sub>.
The domain &#x2124;<sub>q</sub> is simply too large even when using the minimal security parameters. Assuming a 256-bit sized q the number of possible values equals roughly the 
number of the elementary particles within the visible universe.

Another question is whether the entropy sources of conventional computer systems can be trusted. See the article [Entropy Attacks!](http://blog.cr.yp.to/20140205-entropy.html) within
Bernsteins [cr.yp.to blog](http://blog.cr.yp.to/index.html) for a discussion. Someone might remember the 
[Debian random number debacle](https://www.debian.org/security/2008/dsa-1571) too. Fortunately, there are methods available to generate the required nonces without access to high quality
randomness. [Ed25519](http://ed25519.cr.yp.to/ed25519-20110926.pdf) generates the nonce by computing 
<p align="center">r &#x2261; H(h<sub>b</sub>, ... , h<sub>2b−1</sub> || M)</p>
whereas (h<sub>b</sub>, ... , h<sub>2b−1</sub>) is part of the hashed (secret) private key. My problem with this approach is that even SHA-512 produces only a 512-bit output and 
that aren't enough bits to compute an uniformly distributed r &#x220A;<sub>R</sub> (&#x2124;<sub>q</sub>)<sup>&#x00D7;</sup>, assuming a 512-bit sized q (which is the default). For this
purpose H would have to output at least 512 + k bits thus producing a distribution with a statistical distance of at most 2<sup>-k</sup> to the uniform distribution. The subsequent
<p align="center">r &#x2261;<sub>q</sub> SHA-512(x || M), &#x2308;log<sub>2</sub> q&#x2309; = 512</p>
would therefore produce a biased nonce. This isn't a problem for [Ed25519](http://ed25519.cr.yp.to/ed25519-20110926.pdf) because they are reducing r by a 252-bit sized modulus.
See also section 9.2 "Generating a random number from a given interval" within Shoup's [A Computational Introduction to Number Theory and Algebra](http://www.shoup.net/ntb/). 

Instead, I have followed [RFC 6979](https://tools.ietf.org/html/rfc6979)
which describes the "Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)". At the heart of 
[RFC 6979](https://tools.ietf.org/html/rfc6979) is a PRNG based upon a keyed hash function (HMAC) which can produce an arbitrary number of random bits. 
I'm using HmacSha256 for the given algorithm. HmacSha256 comes with the SunJCE JCA provider that in turn is part of the Oracle JDK (and OpenJDK). 
The `HmacSHA256PRNGNonceGenerator` needs some additional key bytes. Hence its usage must be already considered when generating the key pair.

The deterministic `HmacSHA256PRNGNonceGenerator` can be injected as follows:

```java
import java.io.File;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import de.christofreichardt.crypto.HmacSHA256PRNGNonceGenerator;
import de.christofreichardt.crypto.NonceGenerator;
import de.christofreichardt.crypto.schnorrsignature.SchnorrSigKeyGenParameterSpec;
import de.christofreichardt.crypto.schnorrsignature.SchnorrSigKeyGenParameterSpec.Strength;
import de.christofreichardt.crypto.schnorrsignature.SchnorrSigParameterSpec;
...
KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SchnorrSignature");
SchnorrSigKeyGenParameterSpec schnorrSigKeyGenParameterSpec = new SchnorrSigKeyGenParameterSpec(Strength.DEFAULT, true); // demands extra key bytes
keyPairGenerator.initialize(schnorrSigKeyGenParameterSpec);
KeyPair keyPair = keyPairGenerator.generateKeyPair();
File file = new File("loremipsum.txt");
byte[] bytes = Files.readAllBytes(file.toPath());
Signature signature = Signature.getInstance("SchnorrSignature");
NonceGenerator nonceGenerator = new HmacSHA256PRNGNonceGenerator();
SchnorrSigParameterSpec schnorrSigParameterSpec = new SchnorrSigParameterSpec(nonceGenerator);
signature.setParameter(schnorrSigParameterSpec);
signature.initSign(keyPair.getPrivate());
signature.update(bytes);
byte[] signatureBytes = signature.sign();
signature.initVerify(keyPair.getPublic());
signature.update(bytes);
boolean verified = signature.verify(signatureBytes);
assert verified;
```

As a consequence, if someone signs a document twice with the `HmacSHA256PRNGNonceGenerator` the produced signatures will be the same contrary to the traditional protocol because 
the generated nonces depend only on the to be signed message and on portions of the private key.

By default the `Signature` engine uses the `AlmostUniformRandomNonceGenerator` class together with a `SecureRandom` instance. This `AlmostUniformRandomNonceGenerator`
produces the nonce r by requesting t random bits with
<p align="center">t = &#x2308;log<sub>2</sub> q&#x2309;&#x22C5;2</p>
and summing up the corresponding powers of 2 thus ensuring an almost uniform distribution over &#x2124;<sub>q</sub>. 
As alternative an `UniformRandomNonceGenerator` can be injected into the `Signature` engine. This one produces a perfect uniform distribution over &#x2124;<sub>q</sub>. The
`UniformRandomNonceGenerator` has the disadvantage that its runtime is probabilistic whereas the `AlmostUniformRandomNonceGenerator` has a constant runtime. Since the
`UniformRandomNonceGenerator` doesn't need extra key bytes the following code is suffcient to inject it into the `Signature` engine:

```java
import java.io.File;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import de.christofreichardt.crypto.NonceGenerator;
import de.christofreichardt.crypto.UniformRandomNonceGenerator;
import de.christofreichardt.crypto.schnorrsignature.SchnorrSigParameterSpec;
...
KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SchnorrSignature");
KeyPair keyPair = keyPairGenerator.generateKeyPair();
File file = new File("loremipsum.txt");
byte[] bytes = Files.readAllBytes(file.toPath());
Signature signature = Signature.getInstance("SchnorrSignature");
NonceGenerator nonceGenerator = new UniformRandomNonceGenerator();
SchnorrSigParameterSpec schnorrSigParameterSpec = new SchnorrSigParameterSpec(nonceGenerator);
signature.setParameter(schnorrSigParameterSpec);
signature.initSign(keyPair.getPrivate());
signature.update(bytes);
byte[] signatureBytes = signature.sign();
signature.initVerify(keyPair.getPublic());
signature.update(bytes);
boolean verified = signature.verify(signatureBytes);
assert verified;
```

[TOC](#TOC)

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

### <a name="EllipticCurveKeyPair"></a>4.i KeyPairGenerator Usage

Key pairs can be generated by using some well known compilations of cryptographically strong curves. The 'Bundesamt für Sicherheit in der Informationstechnik'
in its [Technical Guideline TR-03111](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03111/BSI-TR-03111_pdf.pdf?__blob=publicationFile) recommends the use
of the curves provided by the ECC Brainpool working group, which have been published by the [RFC 5639](https://tools.ietf.org/html/rfc5639). This JCA provider uses this curve
compilation as default. The NIST recommended elliptic curves over prime fields specified by [FIPS PUB 186-4](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf) can be used too. 
Curves of both compilations have been critizised by the researchers [Daniel J. Bernstein](http://cr.yp.to/djb.html) and [Tanja Lange](http://hyperelliptic.org/tanja/) for
various reasons, see their site [SafeCurves: choosing safe curves for elliptic-curve cryptography](http://safecurves.cr.yp.to/index.html) for more information. This library 
therefore provides some curves recommended by this site as well. So long as all required domain parameter are provided the user may also apply arbitrary curves of his own choice.

#### <a name="EllipticCurveKeyPair1"></a>4.i.a Brainpool Curves

[RFC 5639](https://tools.ietf.org/html/rfc5639) defines curves for each of the bit lengths 160, 192, 224, 256, 320, 384 and 512 together with corresponding twist curves. 
The 256-bit curve 'brainpoolP256r1' is used as default. All curves exhibit a prime number as group order, hence all points of a particular curve may serve
as basepoints. Nevertheless [RFC 5639](https://tools.ietf.org/html/rfc5639) specifies additionally a basepoint for each curve. This one will be used as default:

```java
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import de.christofreichardt.crypto.ecschnorrsignature.CurveSpec;
import de.christofreichardt.crypto.ecschnorrsignature.ECSchnorrPublicKey;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesWithPrimeField.AffinePoint;
...
KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECSchnorrSignature");
KeyPair keyPair = keyPairGenerator.generateKeyPair();
ECSchnorrPublicKey publicKey = (ECSchnorrPublicKey) keyPair.getPublic();
CurveSpec curveSpec = publicKey.getEcSchnorrParams().getCurveSpec();
BigInteger p = curveSpec.getCurve().p().bigInteger();
AffinePoint basePoint = curveSpec.getgPoint();
BigInteger order = curveSpec.getOrder();
assert p.bitLength() == 256;
assert p.isProbablePrime(100) && order.isProbablePrime(100);
assert basePoint.equals(publicKey.getEcSchnorrParams().getgPoint());
assert basePoint.multiply(order).isNeutralElement();
```

The next examples demonstrates how someone may retrieve a Brainpool curve with a particular bit length:

```java
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import de.christofreichardt.crypto.ecschnorrsignature.CurveSpec;
import de.christofreichardt.crypto.ecschnorrsignature.ECSchnorrPublicKey;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesWithPrimeField.AffinePoint;
...
final int BIT_LENGTH = 384;
KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECSchnorrSignature");
keyPairGenerator.initialize(BIT_LENGTH);
KeyPair keyPair = keyPairGenerator.generateKeyPair();
ECSchnorrPublicKey publicKey = (ECSchnorrPublicKey) keyPair.getPublic();
CurveSpec curveSpec = publicKey.getEcSchnorrParams().getCurveSpec();
BigInteger p = curveSpec.getCurve().p().bigInteger();
AffinePoint basePoint = curveSpec.getgPoint();
BigInteger order = curveSpec.getOrder();
assert p.isProbablePrime(100) && order.isProbablePrime(100);
assert p.bitLength() == BIT_LENGTH;
assert basePoint.equals(publicKey.getEcSchnorrParams().getgPoint());
assert basePoint.multiply(order).isNeutralElement();
```

The above example retrieves the `brainpoolP384r1` curve. For every `brainpoolPnnnr1` curve exists a twist curve `brainpoolPnnnt1` with a similar security profile whereas `nnn` denotes
one of the valid bit lengths. The subsequent example retrieves the curve `brainpoolP224t1` and demands a random base point which will be generated by the given `SHA1PRNG` SecureRandom
instance:

```java
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import de.christofreichardt.crypto.ecschnorrsignature.CurveSpec;
import de.christofreichardt.crypto.ecschnorrsignature.ECSchnorrPublicKey;
import de.christofreichardt.crypto.ecschnorrsignature.ECSchnorrSigKeyGenParameterSpec;
import de.christofreichardt.crypto.ecschnorrsignature.ECSchnorrSigKeyGenParameterSpec.CurveCompilation;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesWithPrimeField.AffinePoint;
...
KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECSchnorrSignature");
final int BIT_LENGTH = 224;
final String CURVE_ID = "brainpoolP224t1";
ECSchnorrSigKeyGenParameterSpec ecSchnorrSigKeyGenParameterSpec = new ECSchnorrSigKeyGenParameterSpec(CurveCompilation.BRAINPOOL, CURVE_ID, true);
keyPairGenerator.initialize(ecSchnorrSigKeyGenParameterSpec, SecureRandom.getInstance("SHA1PRNG"));
KeyPair keyPair = keyPairGenerator.generateKeyPair();
ECSchnorrPublicKey publicKey = (ECSchnorrPublicKey) keyPair.getPublic();
CurveSpec curveSpec = publicKey.getEcSchnorrParams().getCurveSpec();
BigInteger p = curveSpec.getCurve().p().bigInteger();
AffinePoint basePoint = publicKey.getEcSchnorrParams().getgPoint();
BigInteger order = curveSpec.getOrder();
assert p.isProbablePrime(100) && order.isProbablePrime(100);
assert p.bitLength() == BIT_LENGTH;
assert basePoint.multiply(order).isNeutralElement();
```

#### <a name="EllipticCurveKeyPair2"></a>4.i.b NIST Curves

[FIPS PUB 186-4](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf) specifies five curves over prime fields: P-192, P-224, P-256, P-384 and P-521.
The next example shows how someone may create key pairs based upon the `P-384` curve and the specified default base point:

```java
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import de.christofreichardt.crypto.ecschnorrsignature.CurveSpec;
import de.christofreichardt.crypto.ecschnorrsignature.ECSchnorrPublicKey;
import de.christofreichardt.crypto.ecschnorrsignature.ECSchnorrSigKeyGenParameterSpec;
import de.christofreichardt.crypto.ecschnorrsignature.ECSchnorrSigKeyGenParameterSpec.CurveCompilation;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesWithPrimeField.AffinePoint;
...
KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECSchnorrSignature");
final int BIT_LENGTH = 384;
final String CURVE_ID = "P-384";
ECSchnorrSigKeyGenParameterSpec ecSchnorrSigKeyGenParameterSpec = new ECSchnorrSigKeyGenParameterSpec(CurveCompilation.NIST, CURVE_ID);
keyPairGenerator.initialize(ecSchnorrSigKeyGenParameterSpec);
KeyPair keyPair = keyPairGenerator.generateKeyPair();
ECSchnorrPublicKey publicKey = (ECSchnorrPublicKey) keyPair.getPublic();
CurveSpec curveSpec = publicKey.getEcSchnorrParams().getCurveSpec();
BigInteger p = curveSpec.getCurve().p().bigInteger();
AffinePoint basePoint = curveSpec.getgPoint();
BigInteger order = curveSpec.getOrder();
assert p.isProbablePrime(100) && order.isProbablePrime(100);
assert p.bitLength() == BIT_LENGTH;
assert basePoint.equals(publicKey.getEcSchnorrParams().getgPoint());
assert basePoint.multiply(order).isNeutralElement();
```

Again, all curves of the NIST compilation exhibit a prime number as group order.

#### <a name="EllipticCurveKeyPair3"></a>4.i.c SafeCurves

[SafeCurves](http://safecurves.cr.yp.to/index.html) lists several curves which passes their criteria. I have included M-221, Curve25519, M-383 and M-511
into this library to cover a wide range of security levels. Curve25519 had been introduced by Bernstein himself whereas M-221, M-383 and M-511 have
been designed by Aranha et al, see their paper [A note on high-security general-purpose elliptic curves](http://eprint.iacr.org/2013/647.pdf). All of
these curves can be expressed as Montgomery curves and will be processed by the corresponding group law from this library. The next examples shows
how someone may compute key pairs based upon the `M-551` curve with a random base point:

```java
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import de.christofreichardt.crypto.ecschnorrsignature.CurveSpec;
import de.christofreichardt.crypto.ecschnorrsignature.ECSchnorrPublicKey;
import de.christofreichardt.crypto.ecschnorrsignature.ECSchnorrSigKeyGenParameterSpec;
import de.christofreichardt.crypto.ecschnorrsignature.ECSchnorrSigKeyGenParameterSpec.CurveCompilation;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesWithPrimeField.AffinePoint;
...
KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECSchnorrSignature");
final int BIT_LENGTH = 511;
final String CURVE_ID = "M-511";
ECSchnorrSigKeyGenParameterSpec ecSchnorrSigKeyGenParameterSpec = new ECSchnorrSigKeyGenParameterSpec(CurveCompilation.SAFECURVES, CURVE_ID, true);
keyPairGenerator.initialize(ecSchnorrSigKeyGenParameterSpec);
KeyPair keyPair = keyPairGenerator.generateKeyPair();
ECSchnorrPublicKey publicKey = (ECSchnorrPublicKey) keyPair.getPublic();
CurveSpec curveSpec = publicKey.getEcSchnorrParams().getCurveSpec();
BigInteger p = curveSpec.getCurve().p().bigInteger();
AffinePoint basePoint = publicKey.getEcSchnorrParams().getgPoint();
BigInteger order = curveSpec.getOrder();
assert p.isProbablePrime(100) && order.isProbablePrime(100);
assert p.bitLength() == BIT_LENGTH;
assert basePoint.multiply(order).isNeutralElement();
```

All of these curves (M-221, Curve25519, M-383 and M-511) exhibit 8 as cofactor, hence #E(&#x1D53D;<sub>p</sub>)=n&#x22C5;8. 

#### <a name="EllipticCurveKeyPair4"></a>4.i.d Custom Curves

Someone might want to inject curves of his own choice. The subsequent example shows how this can be achieved by defining a ShortWeierstrass curve
found in "Elliptic Curves in Cryptography" by Blake, Seroussi and Smart:

```java
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import scala.math.BigInt;
import de.christofreichardt.crypto.ecschnorrsignature.CurveSpec;
import de.christofreichardt.crypto.ecschnorrsignature.ECSchnorrPublicKey;
import de.christofreichardt.crypto.ecschnorrsignature.ECSchnorrSigKeyGenParameterSpec;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesWithPrimeField.AffinePoint;
import de.christofreichardt.scala.ellipticcurve.affine.AffineCoordinatesWithPrimeField.PrimeField;
import de.christofreichardt.scala.ellipticcurve.affine.ShortWeierstrass;
import de.christofreichardt.scala.ellipticcurve.affine.ShortWeierstrass.OddCharCoefficients;
...
BigInteger a = new BigInteger("10");
BigInteger b = new BigInteger("1343632762150092499701637438970764818528075565078");
BigInteger p = new BigInteger("2").pow(160).add(new BigInteger("7"));
BigInteger order = new BigInteger("1461501637330902918203683518218126812711137002561");
OddCharCoefficients coefficients = new OddCharCoefficients(new BigInt(a), new BigInt(b));
PrimeField primeField = ShortWeierstrass.makePrimeField(new BigInt(p));
ShortWeierstrass.Curve curve = ShortWeierstrass.makeCurve(coefficients, primeField);
CurveSpec curveSpec = new CurveSpec(curve, order, BigInteger.ONE, null);
KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECSchnorrSignature");
ECSchnorrSigKeyGenParameterSpec ecSchnorrSigKeyGenParameterSpec = new ECSchnorrSigKeyGenParameterSpec(curveSpec, true);
keyPairGenerator.initialize(ecSchnorrSigKeyGenParameterSpec);
KeyPair keyPair = keyPairGenerator.generateKeyPair();
ECSchnorrPublicKey publicKey = (ECSchnorrPublicKey) keyPair.getPublic();
AffinePoint basePoint = publicKey.getEcSchnorrParams().getgPoint();
assert basePoint.multiply(order).isNeutralElement();
```

### <a name="EllipticCurveSignature"></a>4.ii Signature Usage

Once you have generated a key pair with one of the methods outlined above, you may create digital signatures. Signing is done with the private key whereas the
verification process is done with the public key. All considerations regarding the generation of the nonces are the same as in the sections 3.ii.b [Custom SecureRandom](#PrimeFieldsSignature2)
and 3.ii.e [(Deterministic) NonceGenerators](#PrimeFieldsSignature5) of the chapter 3. [Schnorr Signatures on prime fields](#PrimeFields) and therefore the corresponding sections
within this chapter will focus on examples.

#### <a name="EllipticCurveSignature1"></a>4.ii.a Simple Use

This works very similar as 3.ii.a [Simple Use](#PrimeFieldsSignature1) in chapter 3. [Schnorr Signatures on prime fields](#PrimeFields). In fact, since the JCA architecture is generic
regarding algorithms this isn't surprising.

```java
import java.io.File;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
...
KeyPair keyPair = ...
File file = new File("loremipsum.txt");
byte[] bytes = Files.readAllBytes(file.toPath());
Signature signature = Signature.getInstance("ECSchnorrSignature");
signature.initSign(keyPair.getPrivate());
signature.update(bytes);
byte[] signatureBytes = signature.sign();
signature.initVerify(keyPair.getPublic());
signature.update(bytes);
boolean verified = signature.verify(signatureBytes);
assert verified;
```

#### <a name="EllipticCurveSignature2"></a>4.ii.b Custom SecureRandom

Someone might pursue her own strategy regarding RNGs, seeds and entropy sources. It is therefore possible to inject a custom `SecureRandom`
implementation into the signature algorithm:

```java
import java.io.File;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
...
KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECSchnorrSignature");
KeyPair keyPair = keyPairGenerator.generateKeyPair();
File file = new File("../data/loremipsum.txt");
byte[] bytes = Files.readAllBytes(file.toPath());
SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
Signature signature = Signature.getInstance("ECSchnorrSignature");
signature.initSign(keyPair.getPrivate(), secureRandom);
signature.update(bytes);
byte[] signatureBytes = signature.sign();
signature.initVerify(keyPair.getPublic());
signature.update(bytes);
boolean verified = signature.verify(signatureBytes);
assert verified;    
```

See also 3.ii.b [Custom SecureRandom](#PrimeFieldsSignature2) to understand why the nonces must be unpredictable, unique and confidential.

#### <a name="EllipticCurveSignature3"></a>4.ii.c NIO

Suppose that you want protect a [SEPA](https://de.wikipedia.org/wiki/SEPA) payment file with several thousand payment records against subsequent
modification by applying a digital signature. The above shown approach wouldn't work well since the method `byte[] readAllBytes(Path path)`
is not intended for reading in large files. Use NIO to efficiently process potentially large files instead:

```java
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
...
KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECSchnorrSignature");
KeyPair keyPair = keyPairGenerator.generateKeyPair();
File file = new File("SEPA-payment.xml");
Signature signature = Signature.getInstance("ECSchnorrSignature");
signature.initSign(keyPair.getPrivate());
int bufferSize = 512;
ByteBuffer buffer = ByteBuffer.allocate(bufferSize);
try (FileInputStream fileInputStream = new FileInputStream(file)) {
  FileChannel fileChannel = fileInputStream.getChannel();
  do {
    int read = fileChannel.read(buffer);
    if (read == -1)
      break;
    buffer.flip();
    signature.update(buffer);
    buffer.clear();
  } while(true);
}
byte[] signatureBytes = signature.sign();
...
```

#### <a name="EllipticCurveSignature4"></a>4.ii.d Message Digest configuration

#### <a name="EllipticCurveSignature5"></a>4.ii.e (Deterministic) NonceGenerators

#### <a name="EllipticCurveSignature6"></a>4.ii.f Point Multiplication methods

[TOC](#TOC)

## <a name="Links"></a>5. Links

- [Maven](https://maven.apache.org/)
- [Schnorr Groups](https://en.wikipedia.org/wiki/Schnorr_group)
- [JCA Reference Guide](http://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html)
- [FIPS PUB 186-4](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)
- [Hash Function Requirements for Schnorr Signatures](http://www.neven.org/papers/schnorr.pdf)
- [The Legion of the Bouncy Castle](https://www.bouncycastle.org/java.html)
- [The cr.yp.to blog](http://blog.cr.yp.to/index.html)
- [Ed25519](http://ed25519.cr.yp.to/ed25519-20110926.pdf)
- [A Computational Introduction to Number Theory and Algebra](http://www.shoup.net/ntb/)
- [RFC 6979](https://tools.ietf.org/html/rfc6979)
- [Technical Guideline TR-03111](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03111/BSI-TR-03111_pdf.pdf?__blob=publicationFile)
- [RFC 5639](https://tools.ietf.org/html/rfc5639)
- [SafeCurves: choosing safe curves for elliptic-curve cryptography](http://safecurves.cr.yp.to/index.html)
- [A note on high-security general-purpose elliptic curves](http://eprint.iacr.org/2013/647.pdf)




