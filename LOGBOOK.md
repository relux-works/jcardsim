# Flight Logbook

> Institutional memory. Concise, factual, high-signal.
> Newest entries first. One block per insight.

## 2026-09-13

### 1415 — KeyAgreementImplTest random AIOOBE: EC private scalar written variable-length (BUG-260912-1ispot)
- ROOT CAUSE: `ByteContainer.setBytes` allocates `data` on the first write and never grows it (`ByteContainer.java:108`). `KeyPair.genKeyPair()` reuses the same `ECPrivateKeyImpl` and `KeyAgreementImplTest.testGenerateSecret` calls it twice per KeyPair; a first random scalar with a leading zero byte (~1/256 per FP key) sized the container short, the next full-length scalar overflowed in `Util.arrayCopy`. NOT the 33-byte sign byte named in the bug — `setBigInteger` already strips it.
- FIX: `ECPrivateKeyImpl.setParameters` writes `asUnsignedByteArray((size+7)/8, d)` — left-padded fixed field length. BC 1.46 lacks the `(int, BigInteger)` overload (javap-verified), so a package-private helper does it and refuses a wider scalar.
- FINDING: `getS()` now returns the field length always (32 for P-256, 15 for sect113r1; previously 14 for sect113r1 because the BC generator produced <2^112 scalars).
- EVIDENCE: `ECPrivateKeyImplScalarLengthTest` (3 tests). Mutant A raw `setBigInteger(d)` reproduces the exact flake stack (AIOOBE `byte[1]`); narrowing mutant B (`new byte[raw.length]`) killed by 2 tests. `mvn -q test` 169/169 exit 0; KeyAgreementImplTest x10 all exit 0.
- NOTE: 12-run random reproduction on the unpatched tree did not fire (~4%/run); regression is deterministic instead.

## 2026-09-12

### 0245 — Release 3.0.5.9-relux.1 prepared (TASK-260912-2p0myf)
- MILESTONE: `pom.xml` recoordinated to `works.relux:jcardsim:3.0.5.9-relux.1` over base ph4r05/jcardsim `8414703` + patch `4aae917` (externalAccess parity for MessageDigest/Cipher factories) + patch `10d8d06` (AES-GCM/AES-CTR over BouncyCastle 1.46).
- EVIDENCE: `mvn -q test` 165/165 green exit 0; `mvn -q -DskipTests install` produced `target/jcardsim-3.0.5.9-relux.1.jar` and the matching `~/.m2` copy.
- SCOPE: README fork section and `RELEASE-NOTES-3.0.5.9-relux.1.md` added with javap evidence (`MessageDigest.getInstance` ignores the `externalAccess` boolean; `AEADCipherImpl`/`AESCTRCipherImpl` class shape).
- STATUS: upstream PR body and orchestrator land/tag/release/PR command list prepared as outcome resources; producer did not execute any push/tag/release/PR — that is explicitly the orchestrator's step. Candidate left uncommitted in the Story worktree per handoff contract.

### 0310 — CR rev1 F1 fixed: jar build made reproducible (TASK-260912-2p0myf)
- ROOT CAUSE (review RUN-260911-9aa037, F1): the sha256 quoted in RELEASE-NOTES rev1
  (`ae2a4f36...`) was not reproducible — two independent `mvn -q -DskipTests install` rebuilds of
  the same tree produced two different hashes, neither matching the recorded one. `maven-shade-plugin`
  was pinned at `1.7`, which predates Reproducible Builds support (needs >= 3.2.2), and no
  `project.build.outputTimestamp` was set, so per-entry zip/jar timestamps varied build to build.
- FIX: pinned `project.build.outputTimestamp` to `2019-12-16T00:00:00Z` (base 3.0.5.9 release
  date); bumped `maven-shade-plugin` 1.7 -> 3.5.1 and pinned `maven-jar-plugin` explicitly at 3.5.0
  (already the default-bound version under this Maven, so no behavior change there, just
  reproducibility guarantee made explicit).
- EVIDENCE: two consecutive `mvn -q clean` + `mvn -q -DskipTests install` cycles from the same
  source tree, JDK 17, `JC_CLASSIC_HOME=/private/tmp/jc_classic_home`, produced byte-identical
  jars: `target/jcardsim-3.0.5.9-relux.1.jar` sha256
  `fd6e1289d0a337c5ac1dc9624bc46cf8717bd162228d8d801ada9615ba3d122a` both times, matching the
  `~/.m2` install copy. The `-android` shaded jar was checked the same way and is also
  reproducible: `987826822cda0ddf6db57962b3337b36f53eb4db7e4902a4f38f52f196d6681d` both times.
  `mvn -q test` reran green 165/165 on the first try this time (no flake hit; BUG-260912-1ispot
  remains a disclosed known flake from the CR rev1 evidence, not reproduced here).
- SCOPE: RELEASE-NOTES-3.0.5.9-relux.1.md updated with the reproducible hash and the
  outputTimestamp/plugin-version rationale; orchestrator-commands outcome updated so the release
  step verifies the rebuilt jar's sha256 against RELEASE-NOTES before `gh release create` and
  fails closed on mismatch instead of trusting a hardcoded value.

### 0219 — CTR doFinal reuse fixed after CR rev3 (TASK-260912-yxkqq2)
- ROOT CAUSE (review RUN-260911-e75515, F1): `AESCTRCipherImpl.doFinal` set `isInitialized=false`, so any second `doFinal`/`update` on the same instance threw `INVALID_INIT`, contradicting the `Cipher.doFinal` contract (object resets to its initialized state for further processing).
- FIX: `doFinal` now restores `counter` from a saved `initialCounter` snapshot and resets `keyStreamOffset` to `BLOCK_SIZE` instead of clearing `isInitialized`, mirroring `AEADCipherImpl.resetState`.
- SCOPE: replaced the pinning row in `testCtrNegativeRows` (second `doFinal` → `INVALID_INIT`) with `testCtrDoFinalResetsForReuse`, a reuse positive control (whole-vector doFinal x2, then update+doFinal split doFinal x3, all identical to the F.5.1 ciphertext). GCM/`AEADCipherImpl` untouched per the accepted rev2 verdict.
- EVIDENCE: 4 mutants killed — verifyTag→true (3 GCM tests fail), 15/16-byte tag compare (1 GCM test fails), CTR no-increment (7 CTR tests fail), counter-not-reset-on-doFinal (1 test fails: `testCtrDoFinalResetsForReuse`). `mvn -q test` 165/165 green exit 0; `mvn -q -DskipTests package` exit 0.

### 0152 — AES-GCM / AES-CTR added to the simulator over BC 1.46 (TASK-260912-yxkqq2)
- FINDING: bcprov-jdk14 1.46 already ships `GCMBlockCipher`, `SICBlockCipher`, `AEADParameters` — no BC bump needed for GCM. It has NO `processAADBytes`: AAD goes in only through `AEADParameters`, so `AEADCipherImpl.updateAAD` re-inits the engine (legal until the first data byte; later → ILLEGAL_USE).
- CORRECTION (rev2, after review RUN-260911-02c5f7): rev1 implemented the JCE tag model (encrypt doFinal appended the tag, decrypt expected ct||tag and verified in doFinal). That contradicts the Java Card 3.0.5 `AEADCipher` javadoc and broke the keyvault-crypto-lib witness (decrypt doFinal of 1 byte threw NegativeArraySizeException). Rewritten: MODE_ENCRYPT doFinal emits ciphertext only, tag via `retrieveTag(buf,off,tagLen)`; MODE_DECRYPT doFinal emits plaintext WITHOUT verifying, `verifyTag` returns false on mismatch (no exception, constant-time compare); tag calls before doFinal / wrong mode → ILLEGAL_USE; unsupported tag length → ILLEGAL_VALUE.
- FINDING: BC 1.46 `GCMBlockCipher` decrypt holds the trailing macSize input bytes back as the tag and `doFinal` writes the plaintext AND sets `macBlock` BEFORE comparing. `AEADCipherImpl` therefore appends a zero placeholder tag on decrypt, ignores BC's `InvalidCipherTextException`, and keeps `getMac()` for `verifyTag`. Output byte count = input byte count on both modes.
- DECISION: `init(Key, mode)` for GCM uses a 12-byte zero IV as the javadoc says (rev1 threw ILLEGAL_VALUE). The 8-arg "offline" init is accepted for GCM too (javadoc says INVALID_INIT for online modes) because it is the only way to select a tag size < 16; recorded as a deliberate deviation.
- DECISION: `AESCTRCipherImpl` keeps its own 128-bit big-endian counter over BC `AESEngine` instead of `SICBlockCipher`, so the "counter not incremented" mutant lives in repo source. Pinned by SP 800-38A F.5.1/F.5.3/F.5.5 and a wrap test.
- DECISION: engine use before any init → INVALID_INIT (Cipher API reason, same as SymmetricCipherImpl); key-level problems → UNINITIALIZED_KEY / ILLEGAL_VALUE; out-of-order tag calls → ILLEGAL_USE; tag mismatch is a `verifyTag` false, never an exception.
- BOUND: JC 3.0.5 has no `CIPHER_AES_CTR` constant; CTR `getCipherAlgorithm()` returns CIPHER_AES_ECB. CCM not implemented.

### 0135 — externalAccess=true refused by MessageDigest/Cipher factories (3.0.5.9)
- ROOT CAUSE: `MessageDigestProxy.getInstance`/`getInitializedMessageDigestInstance` and `CipherProxy.getInstance` threw `CryptoException.NO_SUCH_ALGORITHM` unconditionally when `externalAccess=true`; Signature/KeyAgreement never had that gate, so applets using shared engines failed only for digests and ciphers.
- FIX: gate removed in `src/main/java/com/licel/jcardsim/crypto/MessageDigestProxy.java` and `CipherProxy.java`; flag is now a no-op like the other factories (simulator has no CLEAR_ON_DESELECT distinction for engine buffers).
- FINDING: `javacard.security.*` / `javacardx.crypto.*` sources do not exist in the repo; the build injects `*Proxy` classes into the Oracle api_classic classes, so bytecode verification must be done with `javap` on the built jar.
- SCOPE: `ExternalAccessFactoryParityTest` pins parity for all four factories plus unknown-algorithm negative row. TASK-260912-2ehtym.
