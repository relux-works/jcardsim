# jcardsim 3.0.5.9-relux.1

Fork of [ph4r05/jcardsim](https://github.com/ph4r05/jcardsim) 3.0.5.9
(base commit [8414703](https://github.com/ph4r05/jcardsim/commit/8414703)), republished as
`works.relux:jcardsim:3.0.5.9-relux.1` (coordinate change only — no upstream commit carries it).

## Patch 1 — externalAccess parity for MessageDigest/Cipher factories

**Defect.** `MessageDigestProxy.getInstance`, `MessageDigestProxy.getInitializedMessageDigestInstance`,
and `CipherProxy.getInstance` unconditionally threw `CryptoException.NO_SUCH_ALGORITHM` when called
with `externalAccess=true`. `Signature.getInstance`/`KeyAgreement.getInstance` had no such gate, so an
applet requesting a shared (external-access) `MessageDigest` or `Cipher` engine failed while the
equivalent `Signature`/`KeyAgreement` request succeeded — an inconsistency with no basis in the
Java Card 3.0.5 API contract (the simulator has no CLEAR_ON_DESELECT distinction for engine buffers,
so there was nothing for the gate to protect).

**Fix.** `src/main/java/com/licel/jcardsim/crypto/MessageDigestProxy.java` and
`src/main/java/com/licel/jcardsim/crypto/CipherProxy.java`: the `externalAccess` flag is now a no-op,
matching `SignatureProxy`/`KeyAgreementProxy`.

**Evidence (javap on the woven `javacard.security.MessageDigest` class in the built jar):**

```
public static final javacard.security.MessageDigest getInstance(byte, boolean) throws javacard.security.CryptoException;
  Code:
     0: new           #73     // class com/licel/jcardsim/crypto/MessageDigestImpl
     3: dup
     4: iload_0
     5: invokespecial #76     // Method com/licel/jcardsim/crypto/MessageDigestImpl."<init>":(B)V
     8: astore_2
     9: aload_2
    10: areturn
```

The boolean `externalAccess` argument (local slot 1) is never read — the method constructs
`MessageDigestImpl` unconditionally, for both `true` and `false`.

**Tests.** `ExternalAccessFactoryParityTest` (`src/test/java/com/licel/jcardsim/crypto/`) pins parity
across `MessageDigest`, `Cipher`, `Signature`, `KeyAgreement` factories for `externalAccess=true`, plus
an unknown-algorithm negative row (still throws `NO_SUCH_ALGORITHM` regardless of the flag).

## Patch 2 — AES-GCM / AES-CTR engines over BouncyCastle

**Defect.** The simulator had no `javacardx.crypto.AEADCipher` (AES-GCM) or AES-CTR implementation,
even though `bcprov-jdk14` 1.46 (already a dependency) ships `GCMBlockCipher`, `SICBlockCipher`, and
`AEADParameters` capable of backing both.

**Fix.** Adds `AEADCipherImpl` (AES-GCM) and `AESCTRCipherImpl` (AES-CTR), wired into `CipherProxy`.

**Contract notes / stated bounds:**

- BC 1.46's `GCMBlockCipher` has no `processAADBytes`; AAD only enters through `AEADParameters`, so
  `AEADCipherImpl.updateAAD` re-initializes the engine. This is legal only before the first data byte;
  calling it after data has been processed throws `ILLEGAL_USE`.
- Tag handling follows the Java Card 3.0.5 `AEADCipher` javadoc, not the JCE model: on
  `MODE_ENCRYPT`, `doFinal` emits ciphertext only — the tag is retrieved separately via
  `retrieveTag(buf, off, tagLen)`. On `MODE_DECRYPT`, `doFinal` emits plaintext without verifying;
  `verifyTag` performs a constant-time compare and returns `false` on mismatch (never an exception).
  Tag calls out of order, or a `retrieveTag`/`verifyTag` call in the wrong mode, throw `ILLEGAL_USE`.
  An unsupported tag length throws `ILLEGAL_VALUE`.
- `init(Key, mode)` for GCM uses a 12-byte zero IV per the javadoc. The 8-arg "offline" init
  (`init(Key, mode, byte[] params, short, short, short, short, short)`) is also accepted for GCM as a
  deliberate deviation — it is the only way to select a tag length shorter than 16 bytes; the javadoc
  otherwise reserves that overload for INVALID_INIT on "online" modes.
- `AESCTRCipherImpl` keeps its own 128-bit big-endian counter over BC's `AESEngine` rather than
  `SICBlockCipher`, so the "counter not incremented" failure class lives in this repo's source and is
  covered by a narrowing mutant (see Gates below).
- Java Card 3.0.5 has no `CIPHER_AES_CTR` constant; `AESCTRCipherImpl.getCipherAlgorithm()` returns
  `CIPHER_AES_ECB`. CCM is not implemented.
- Engine used before any `init` → `INVALID_INIT` (same reason code as `SymmetricCipherImpl`); key-level
  problems → `UNINITIALIZED_KEY` / `ILLEGAL_VALUE`.
- `doFinal`/`update` reuse: after a `doFinal`, the CTR counter is restored from an `initialCounter`
  snapshot and `keyStreamOffset` reset, so the cipher object is reusable for a further
  `init`-less `doFinal`/`update` sequence, per the `Cipher.doFinal` contract (object resets to its
  initialized state).

**Tests.** `AESGCMCTRCipherTest` — SP 800-38A F.5.1/F.5.3/F.5.5 CTR test vectors plus a counter-wrap
test, GCM encrypt/decrypt/tag-mismatch/AAD-reinit/negative-row coverage, and a
`testCtrDoFinalResetsForReuse` positive control (whole-vector `doFinal` x2, then
`update`+`doFinal` split `doFinal` x3, all producing the same F.5.1 ciphertext).

## Known flake (not fixed in this release)

`KeyAgreementImplTest` has an intermittent flake tracked as `BUG-260912-1ispot`. It is not addressed
by this release; `mvn -q test` passed 165/165 in the verification run below.

## Gates (mutant evidence)

| Mutant | Narrows | Failing test | Bound stated |
| --- | --- | --- | --- |
| GCM `verifyTag` always returns `true` | tag verification | 3 GCM tests in `AESGCMCTRCipherTest` | tag mismatch must be detectable |
| GCM tag compare uses 15 of 16 bytes | tag-length correctness | 1 GCM test in `AESGCMCTRCipherTest` | full tag must be compared |
| CTR counter not incremented between blocks | keystream generation | 7 CTR tests in `AESGCMCTRCipherTest` | counter must advance per block |
| CTR counter not reset/restored on `doFinal` | reuse contract | `testCtrDoFinalResetsForReuse` | object must remain reusable after `doFinal` |

## Build verification

```
$ mvn -q test
Tests run: 165, Failures: 0, Errors: 0, Skipped: 0
$ echo $?
0

$ mvn -q -DskipTests install
$ echo $?
0
```

## Artifact

The build is reproducible: `project.build.outputTimestamp` is pinned to `2019-12-16T00:00:00Z`
(the base 3.0.5.9 release date) and `maven-jar-plugin`/`maven-shade-plugin` are bumped to
versions that honour it (jar plugin 3.5.0, shade plugin 3.5.1 — the previous shade 1.7 predates
Reproducible Builds support, which requires >= 3.2.2). Verified reproducible given JDK 17 and the
pinned timestamp: two consecutive `mvn -q clean` + `mvn -q -DskipTests install` cycles from the
same source tree produced byte-identical jars.

- `target/jcardsim-3.0.5.9-relux.1.jar`
  sha256: `fd6e1289d0a337c5ac1dc9624bc46cf8717bd162228d8d801ada9615ba3d122a`
- `~/.m2/repository/works/relux/jcardsim/3.0.5.9-relux.1/jcardsim-3.0.5.9-relux.1.jar`
  sha256: `fd6e1289d0a337c5ac1dc9624bc46cf8717bd162228d8d801ada9615ba3d122a`
- `target/jcardsim-3.0.5.9-relux.1-android.jar` (shaded, Android classifier; part of this release)
  sha256: `987826822cda0ddf6db57962b3337b36f53eb4db7e4902a4f38f52f196d6681d`

(target jar, installed ~/.m2 jar, and a second clean rebuild all match; android shaded jar
verified reproducible the same way)
