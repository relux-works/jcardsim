# Flight Logbook

> Institutional memory. Concise, factual, high-signal.
> Newest entries first. One block per insight.

## 2026-09-12

### 0135 — externalAccess=true refused by MessageDigest/Cipher factories (3.0.5.9)
- ROOT CAUSE: `MessageDigestProxy.getInstance`/`getInitializedMessageDigestInstance` and `CipherProxy.getInstance` threw `CryptoException.NO_SUCH_ALGORITHM` unconditionally when `externalAccess=true`; Signature/KeyAgreement never had that gate, so applets using shared engines failed only for digests and ciphers.
- FIX: gate removed in `src/main/java/com/licel/jcardsim/crypto/MessageDigestProxy.java` and `CipherProxy.java`; flag is now a no-op like the other factories (simulator has no CLEAR_ON_DESELECT distinction for engine buffers).
- FINDING: `javacard.security.*` / `javacardx.crypto.*` sources do not exist in the repo; the build injects `*Proxy` classes into the Oracle api_classic classes, so bytecode verification must be done with `javap` on the built jar.
- SCOPE: `ExternalAccessFactoryParityTest` pins parity for all four factories plus unknown-algorithm negative row. TASK-260912-2ehtym.
