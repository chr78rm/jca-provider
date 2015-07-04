# JCA-Provider

A provider for the Java Cryptography Architecture. Implementations are intended for the Schnorr Signature based on prime fields and elliptic curves
as well as for the Rabin-SAEP cryptosystem.

## Build

[Maven](https://maven.apache.org/) is required to compile the library. A whole build will take some time - currently up to three minutes on my laptop. 
This is mainly due to the unit tests belonging to the jca-schnorrsig sub-module. The custom domain parameter generation includes the search 
for random [Schnorr Groups](https://en.wikipedia.org/wiki/Schnorr_group) satisfying specified security limits. 

`mvn clean install`

Experimental test cases concerning the calculation of the group order may sometimes fail due to their probabilistic character. 
However this is rather unlikely and a repetition of the build will suffice in most cases.

## Schnorr Signature on prime fields

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

## Schnorr Signature on elliptic curves

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


