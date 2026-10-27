# jcardsim 3.0.5.9-relux.4

Coordinate: `works.relux:jcardsim:3.0.5.9-relux.4`. Retains the relux.3 runtime
and logical-channel behavior.

## GCM initialization

The eight-argument `AEADCipher.init` overload is reserved for offline cipher
modes such as CCM. The previous simulator accepted it for GCM, which could hide
an API violation in consumer code. It now throws exactly
`CryptoException.INVALID_INIT` and invalidates any previous operation.

The legal two- and five-argument GCM initializers share a private initializer;
they no longer delegate to the rejecting public offline overload. Explicit
nonces remain 12 bytes, generated tags remain 16 bytes, and streaming AAD, ciphertext,
tag retrieval/verification and existing CTR behavior are unchanged. An invalid
online reinitialization also leaves no usable previous operation.

This intentionally retires the older extension for configuring shorter GCM tags
through offline init. It introduces neither CCM support nor a compatibility
branch. See the [Java Card 3.0.5 AEADCipher API](https://docs.oracle.com/cd/E59935_01/api/javacardx/crypto/AEADCipher.html).

## Verification

The regression first failed against the unchanged production implementation:
`testGcmOfflineInitRejectedAndOnlineInitRecovers` observed no required exception.
After correction the complete Maven suite passes: 184 tests, zero failures,
errors or skips on JDK 17.0.18 and Maven 3.9.14 with the Java Card 3.0.5u4 kit.

The tests cover both encrypt/decrypt offline-overload rejection, unusable state
after rejection, successful online recovery, NIST vectors, streaming operation,
bad tag/AAD verification and invalid online reinitialization. Decryption still
emits unauthenticated plaintext before `verifyTag`; a wrong tag returns false.
Consumers must enforce that verdict before accepting plaintext.

Reproduce with the existing documented SDK setup:

```sh
export JC_CLASSIC_HOME=/path/to/jc305u4_kit
mvn -q test
mvn -q install
```

No physical-card behavior or complete JCRE conformance is established by these
simulator tests. The reproducible archive timestamp remains unchanged.
