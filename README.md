jCardSim (Official repo of the [jCardSim](http://jcardsim.org) project)
========

## relux-works fork

This repository publishes `works.relux:jcardsim:3.0.5.9-relux.1`, a fork of
[ph4r05/jcardsim](https://github.com/ph4r05/jcardsim) 3.0.5.9
(base commit [8414703](https://github.com/ph4r05/jcardsim/commit/8414703)) with two
patches on top:

1. **externalAccess parity for MessageDigest/Cipher factories.** `MessageDigestProxy`
   and `CipherProxy` unconditionally threw `CryptoException.NO_SUCH_ALGORITHM` when
   `externalAccess=true`, while `Signature`/`KeyAgreement` never had that gate. The
   gate is removed so all four factories behave the same. Verified with `javap` on
   the built jar: `MessageDigest.getInstance(byte, boolean)` now directly constructs
   `MessageDigestImpl` regardless of the boolean argument — see
   `RELEASE-NOTES-3.0.5.9-relux.1.md`.
2. **AES-GCM / AES-CTR engines over BouncyCastle.** Adds `AEADCipherImpl` (AES-GCM,
   over BC's `GCMBlockCipher`) and `AESCTRCipherImpl` (AES-CTR, over BC's
   `AESEngine` with an explicit 128-bit counter), wired into `CipherProxy`. See
   `RELEASE-NOTES-3.0.5.9-relux.1.md` for the JC 3.0.5 `AEADCipher` contract notes
   and stated bounds (AAD re-init behavior, `CIPHER_AES_ECB` reported for CTR,
   8-arg init tag-size deviation).

A PR carrying only these two patches (no coordinate change) is open/planned against
upstream `ph4r05/jcardsim`.

### Consumer coordinate

```xml
<dependency>
    <groupId>works.relux</groupId>
    <artifactId>jcardsim</artifactId>
    <version>3.0.5.9-relux.1</version>
</dependency>
```

### Building / installing locally

This fork depends on `oracle.javacard:api_classic:3.0.5`, which is not published to
any public Maven repository — it comes from the Java Card 3.0.5u4 Classic Edition
SDK kit. One-time setup: point `JC_CLASSIC_HOME` at an unpacked JC 3.0.5u4 kit
(the directory containing `lib/api_classic.jar`). The build's `initialize` phase
runs `install-file` against `${JC_CLASSIC_HOME}/lib/api_classic.jar` automatically
on every `mvn` invocation, so no separate manual step is required once the kit is
available and the environment variable is exported:

```bash
export JC_CLASSIC_HOME=/path/to/jc305u4_kit
mvn -q test
mvn -q -DskipTests install
```

`mvn -q -DskipTests install` produces
`~/.m2/repository/works/relux/jcardsim/3.0.5.9-relux.1/jcardsim-3.0.5.9-relux.1.jar`.

### Congratulations! jCardSim has won [Duke's Choice 2013 Award](https://www.java.net/dukeschoice/2013)!

![alt text](https://licelus.com/wp-content/uploads/DCA2013_Badge_Winner.jpg "jCardSim is a winner of Duke's Choice 2013")

jCardSim is an open source simulator for Java Card, v.2.2/3.0.5:

* `javacard.framework.*`
* `javacard.framework.security.*`
* `javacardx.crypto.*`

Key Features:

* Rapid application prototyping
* Simplifies unit testing (5 lines of code)

```java
// 1. create simulator
CardSimulator simulator = new CardSimulator();

// 2. install applet
AID appletAID = AIDUtil.create("F000000001");
simulator.installApplet(appletAID, HelloWorldApplet.class);

// 3. select applet
simulator.selectApplet(appletAID);

// 4. send APDU
CommandAPDU commandAPDU = new CommandAPDU(0x00, 0x01, 0x00, 0x00);
ResponseAPDU response = simulator.transmitCommand(commandAPDU);

// 5. check response
assertEquals(0x9000, response.getSW());
```

* Emulation of Java Card Terminal, ability to use `javax.smartcardio`
* APDU scripting (scripts are compatible with `apdutool` from Java Card Development Kit)
* Simplifies verification tests creation (Common Criteria)

*JavaDoc*: https://github.com/licel/jcardsim/tree/master/javadoc

  (Javadoc rendered: https://jcardsim.org/jcardsim/)

*Latest stable release 2.2.1*: https://github.com/licel/jcardsim/raw/master/jcardsim-2.2.1-all.jar

*Latest stable release 2.2.2*: https://github.com/licel/jcardsim/raw/master/jcardsim-2.2.2-all.jar

*Maven Central Repository*
```xml
<dependency>
  <groupId>com.klinec</groupId>
  <artifactId>jcardsim</artifactId>
  <version>3.5.0.4</version>
</dependency>
```

### What is the difference from Oracle Java Card Development Kit simulator?

* **Implementation of javacard.security.***

  One of the main differences is the implementation of `javacard.security.*`: the current version is analogous to an NXP JCOP 31/36k card. For example, in jCardSim we have support for on-card `KeyPair.ALG_EC_F2M/ALG_RSA_CRT` key generation. Oracle's simulator only supports `KeyPair.ALG_RSA` and `KeyPair.ALG_EC_FP`, which are not supported by real cards.

* **Execution of Java Card applications without converting into CAP**

  jCardSim can work with class files without any conversions. This allows us to simplify and accelerate the development and writing of unit tests.

* **Simulator API**

  jCardSim has a simple and usable API, which also allows you to work with the simulator using `javax.smartcardio.*`.

* **Cross-platform**

  jCardSim is completely written in Java and can therefore be used on all platforms which support Java (Windows, Linux, MacOS, etc).

### How to help jCardSim?

* Join the team of jCardSim developers.
* Try out [DexProtector](http://dexprotector.com). The product is designed for strong and robust protection of Android applications against reverse engineering and modification.
* Licel has one more product you may be interested in - [Stringer Java Obfuscator](https://jfxstore.com/stringer). This tool provides all the features you need to comprehensively protect your Java applications.

**License**: [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0)

**Third-party libraries**: [Legion of the Bouncy Castle Java](http://www.bouncycastle.org/java.html)

**Trademarks**: Oracle, Java and Java Card are trademarks of Oracle Corporation.
