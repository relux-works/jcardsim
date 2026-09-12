# jcardsim 3.0.5.9-relux.2

Fork of [ph4r05/jcardsim](https://github.com/ph4r05/jcardsim) 3.0.5.9
(base commit [8414703](https://github.com/ph4r05/jcardsim/commit/8414703)), republished as
`works.relux:jcardsim:3.0.5.9-relux.2`. See `RELEASE-NOTES-3.0.5.9-relux.1.md` for the prior
patches (externalAccess parity, AES-GCM/AES-CTR engines).

## Patch 3 — KeyAgreementImplTest random flake fixed: EC private scalar written variable-length (BUG-260912-1ispot)

**Defect / mechanism.** `ECPrivateKeyImpl.setParameters` stored the private scalar with
`s.setBigInteger(d)`, i.e. `BigInteger.toByteArray()` trimmed of its sign byte — a
variable-length encoding. `ByteContainer.setBytes` allocates its backing array on the
*first* write and never grows it (`ByteContainer.java:108`). `KeyPair.genKeyPair()` reuses
the same `ECPrivateKeyImpl` instance across key generations, and `KeyAgreementImplTest`
generates key pairs repeatedly. When the first random scalar happened to have a leading
zero byte (a ~1/256 chance per FP key, so the flake fired only intermittently), the
container sized itself one byte short; the next full-length scalar written into the same
object then overflowed in `Util.arrayCopy` with `ArrayIndexOutOfBoundsException`. This is
not the 33-byte BigInteger sign byte named in the original bug title — `setBigInteger`
already strips that; the actual defect is the *short* first write undersizing a
never-grows container.

**Fix.** `src/main/java/com/licel/jcardsim/crypto/ECPrivateKeyImpl.java`:
`setParameters` now writes `asUnsignedByteArray((short) ((size + 7) / 8), d)` — the scalar
is always left-padded to the fixed EC field length, independent of its own magnitude. BC
1.46 has no `BigIntegers.asUnsignedByteArray(int, BigInteger)` overload (verified via
javap against the bundled jar), so a package-private helper
`ECPrivateKeyImpl.asUnsignedByteArray(short length, BigInteger value)` performs the
left-padding and throws `IllegalArgumentException` if the value does not fit in `length`
bytes (a wider scalar is refused, not silently truncated).

**Side effect.** `ECPrivateKeyImpl.getS()` now always returns the field length (32 bytes
for P-256, 15 for sect113r1) — previously it could return 14 bytes for sect113r1 whenever
the BC generator produced a scalar `< 2^112`, because the stored length tracked the
trimmed encoding.

**Tests.** `ECPrivateKeyImplScalarLengthTest`
(`src/test/java/com/licel/jcardsim/crypto/`), 3 tests:
- `testShortScalarThenFullLengthScalarOnSameKey` — reproduces the flake mechanism
  deterministically (short scalar sizes the container, full-length scalar written next on
  the same key object, as `KeyPair.genKeyPair()` does on reuse).
- `testTopBitSetScalarSetsAndAgrees` — a scalar with the top bit set (33-byte
  `toByteArray()` for P-256) stores at fixed length, round-trips through
  `getParameters()`, and agrees in ECDH through the production `KeyAgreement` entry point.
- `testScalarWiderThanFieldIsRejected` — negative bound: a scalar wider than the field
  length throws `IllegalArgumentException` instead of being truncated.

**Reproduction note.** A 12-run random-reproduction attempt against the unpatched tree did
not reliably fire in bounded local runs (per-run probability ~4%); the regression witness
above reproduces the exact failure deterministically instead of relying on random timing.

## Gates (mutant evidence)

| Mutant | Narrows | Failing test | Bound stated |
| --- | --- | --- | --- |
| `setParameters` reverted to raw `s.setBigInteger(d)` (mutant A) | fixed-length scalar write | `testShortScalarThenFullLengthScalarOnSameKey` (reproduces the exact AIOOBE `byte[1]` overflow stack) | short-then-full-length scalar sequence on one key object must not overflow |
| `asUnsignedByteArray` allocates `new byte[raw.length]` instead of `new byte[length]` (mutant B, narrowing — output length still varies with the scalar, only the allocation site moves) | fixed output length | `testShortScalarThenFullLengthScalarOnSameKey`, `testTopBitSetScalarSetsAndAgrees` | output array length must equal the requested field length regardless of the scalar's own magnitude |

## Known flake status

`BUG-260912-1ispot` is fixed by Patch 3 above. `KeyAgreementImplTest` verified stable
across 10 consecutive standalone runs (see Build verification).

## Build verification

```
$ mvn -q clean
$ mvn -q -DskipTests install   # run 1
$ echo $?
0
$ mvn -q clean
$ mvn -q -DskipTests install   # run 2
$ echo $?
0
$ mvn -q test
Tests run: 168, Failures: 0, Errors: 0, Skipped: 0
$ echo $?
0
$ for i in $(seq 1 10); do mvn -q -Dtest=KeyAgreementImplTest test; echo "run $i exit $?"; done
run 1 exit 0
run 2 exit 0
run 3 exit 0
run 4 exit 0
run 5 exit 0
run 6 exit 0
run 7 exit 0
run 8 exit 0
run 9 exit 0
run 10 exit 0
```

## Build hygiene

`maven-shade-plugin` now sets `<createDependencyReducedPom>false</createDependencyReducedPom>`.
The relux.1 review found `dependency-reduced-pom.xml` being written into the repo root on
every build (an untracked, non-reproducible artifact); the shade plugin no longer generates
it.

## Artifact

The build remains reproducible: `project.build.outputTimestamp` is pinned to
`2019-12-16T00:00:00Z`. Verified reproducible given JDK 17 and the pinned timestamp: two
consecutive `mvn -q clean` + `mvn -q -DskipTests install` cycles from the same source tree
produced byte-identical jars, matching the jar installed into `~/.m2`.

- `target/jcardsim-3.0.5.9-relux.2.jar`
  sha256: `485617e913bef9803404d32d2d4f36b5410bf7d298c3ff147e0e1b4d27d3262a`
- `~/.m2/repository/works/relux/jcardsim/3.0.5.9-relux.2/jcardsim-3.0.5.9-relux.2.jar`
  sha256: `485617e913bef9803404d32d2d4f36b5410bf7d298c3ff147e0e1b4d27d3262a`

(target jar, installed ~/.m2 jar, and a second clean rebuild all match)
