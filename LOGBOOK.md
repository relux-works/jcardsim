# Flight Logbook

> Institutional memory. Concise, factual, high-signal.
> Newest entries first. One block per insight.

## 2026-09-12

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
