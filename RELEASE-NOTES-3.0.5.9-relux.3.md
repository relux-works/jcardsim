# jcardsim 3.0.5.9-relux.3

Coordinate: `works.relux:jcardsim:3.0.5.9-relux.3`. Retains all relux.2 crypto patches.

## Logical channels

The runtime formerly routed every CLA to one global selected applet. Consequently,
B6 sent after a SELECT on channel 0 reached that applet even though B6 codes
logical channel 2. This release intercepts MANAGE CHANNEL (interindustry INS 70),
opens/closes channels 1..19 and keeps a selected AID per channel. Channel 0 stays
open. SELECT uses both first and further ISO CLA encodings. Normal commands retain
the transmitted CLA; APDU.getCLAChannel and JCSystem.getAssignedChannel report the
logical channel. Unopened/closed channels return 6881 before applet dispatch;
reserved CLA FF returns 6E00. An open channel without a selected applet returns 6986.

A non-MultiSelectable instance already active elsewhere refuses another SELECT
with 6985. MultiSelectable callbacks reflect activity on other channels. Closing
or replacing an applet clears its CLEAR_ON_DESELECT arrays only after its last
selection disappears, and does not clear another applet's arrays. Install-time
transient arrays are attributed to the registered instance. Reset closes logical
channels and removes all selections. JCSystem.isAppletActive checks all channels.

Automatic open (`00 70 00 00 01`) returns the lowest free channel; explicit open
(`00 70 00 nn`) returns 9000. Close (`00 70 80 nn`) removes the selected applet;
P2=0 closes the channel in CLA. The runtime refuses duplicate/invalid targets,
basic-channel close, unsupported P1, SM/chaining and data-bearing management frames.
Proprietary INS 70 remains an applet command.

## Verification

`LogicalChannelTest`: 15 named behavioral tests drive Simulator.transmitCommand.
Existing HelloWorld tests keep their names/assertions and send CLA 00 on channel 0
instead of CLA 01; those old fixtures relied on ignored channel bits. Every prior
runtime test, including the relux.2 scalar regression tests, remains present.

Optional `integration/bsimid/BSimAuthLogicalChannelTest.java`: three JUnit 5 tests
compile the actual unchanged Auth applet and generated code from a specified
consumer checkout against this runtime, with the consumer's released Core/Facade
CAP payloads. They require B4 on channel 0, B5/B7 after open + SELECT on channels
1/3, 6881 for B6 after a channel-0 SELECT, 6E00 for foreign classes and FF, 6881 after
close, and 6985 for simultaneous selection of non-MultiSelectable Auth. Refusals
preserve Core key metadata and public identity; unprivileged issuer creation
refuses 6982, with an authenticated issuer positive control that creates keys.
Public identity is the 127-byte SPKI/fingerprint/generation record; unsupported
INS 03 exports no data. Broader key-nonexport claims are outside this routing assay.

The staging harness checks CAP digests and class-byte equality before compiling.
Java remains the host test language; Python only stages inputs and runs independent
Java/Maven processes, keeping the consumer checkout read-only.

## Narrowing controls

| Mutant | Narrows the gate to | Named failing test | Outcome |
| --- | --- | --- | --- |
| unopened-2 | admits only unopened channel 2 | `testB6CannotReachBasicChannelSelection` | Killed; Maven exit 1 |
| borrow-basic-on-2 | borrows basic selection only for unselected channel 2 | `testOpenUnselectedChannelCannotBorrowSelection` | Killed; Maven exit 1 |
| closed-2-open | leaves only closed channel 2 open | `testCloseAndReopenNeverRestoresSelection` | Killed; Maven exit 1 |
| ff-write | admits reserved FF only for state-writing INS 01 | `testReservedFFDoesNotReachSelectedChannel19` | Killed; Maven exit 1 |
| duplicate-1 | admits duplicate open only on channel 1 | `testManageChannelRejectsInvalidTargetsWithoutChangingState` | Killed; Maven exit 1 |
| sm-0c | admits only SM class 0C | `testManageChannelRejectsUnsupportedFraming` | Killed; Maven exit 1 |
| chaining-10 | admits only chained class 10 | `testManageChannelRejectsUnsupportedFraming` | Killed; Maven exit 1 |
| data-open-1 | admits only Case3 open of channel 1 through both framing checks | `testManageChannelRejectsUnsupportedFraming` | Killed; Maven exit 1 |
| single-on-1 | admits a second non-MultiSelectable selection only on channel 1 | `testNonMultiselectableSecondSelectionIsRejected` | Killed; Maven exit 1 |
| failed-select-1 | admits refusing select callback only on channel 1 | `testFailedSelectLeavesChannelUnselected` | Killed; Maven exit 1 |
| cod-other-owner | also clears arrays owned by only fixture applet F00000000201 | `testDeselectDoesNotClearAnotherChannelsTransientState` | Killed; Maven exit 1 |
| basic-close-00 | admits basic-channel close only for CLA 00 | `testManageChannelRejectsInvalidTargetsWithoutChangingState` | Killed; Maven exit 1 |
| close-target-20 | aliases invalid close target 20 to valid target 1; range gate remains | `testManageChannelRejectsInvalidTargetsWithoutChangingState` | Killed; Maven exit 1 |
| open-p1-01 | admits open P1 01 only; all other invalid P1 remain refused | `testManageChannelRejectsInvalidTargetsWithoutChangingState` | Killed; Maven exit 1 |
| issuer-b5 (staged actual Auth) | admits only B5 56 without an issuer session | `channelRefusalsPreserveKeysAndIssuerOnlyCreation` | Killed; JUnit / harness exit 1 |
| foreign-a5 (staged actual Auth) | admits only foreign CLA A5 in process() | `realAuthAcceptsB4B5B7OnlyOnSelectedOpenChannels`, `channelRefusalsPreserveKeysAndIssuerOnlyCreation` | Killed; JUnit / harness exit 1 |

The issuer-B5 staged control admits only B5 56 without a GP service, leaving
all other issuer frames gated. `channelRefusalsPreserveKeysAndIssuerOnlyCreation`
must fail with expected 6982 versus the unauthorized success.

14 of 14 runtime controls and both integration controls are killed by
named assertion failures. No final control survives. The first data-case-only
control survived (Maven exit 0): a second Case1 length check still refused it.
The shipped data-open-1 control weakens both checks only for a Case3 open of
channel 1 and is killed. This records the redundant-gate bound rather than
claiming the initial survivor was detected. No source-text checker substitutes
for the behavioral suites.

## Simulator bounds

This is an APDU routing model, not full JCRE conformance. All newly opened
channels start unselected: there is no default applet selection, and MANAGE
CHANNEL OPEN from a non-basic source does not inherit its applet. SELECT on an
unopened channel returns 6881 rather than implicitly opening it. No
Card.openLogicalChannel adapter is added; use raw Simulator/CardSimulator APDUs.
Package-wide multiselection, package-context transient ownership, real object
firewall checks, transport GET RESPONSE behavior and secure-channel cryptography
are not established here. Transient ownership is per installed applet instance.
The Auth integration uses the existing host GP service fixture to test issuer
level admission, not to attest SCP authentication. No physical card was changed.
Passing these tests does not establish NovaCard eOS class acceptance, memory,
cryptographic capabilities or physical-card logical-channel behavior.

## Reproduction

Use JDK 17, the Java Card 3.0.5u4 SDK and Maven, as documented in README. For example:

```sh
export JAVA_HOME=/path/to/jdk-17
export JC_CLASSIC_HOME=/path/to/jc305u4_kit
mvn -q clean package
mvn -q clean -DskipTests install
python3 scripts/logical-channel-mutants.py
python3 scripts/bsimid-channel-integration.py --bsimid-root /path/to/bsimId --bridge-jar /path/to/jcrpc-bridge-0.3.2.jar
```

The runtime's reproducible ZIP timestamp remains `2019-12-16T00:00:00Z`.
Verified on JDK 17.0.18 / Maven 3.9.14:
- `mvn -q test`: exit 0, 183 tests, no failures/errors/skips.
- `mvn -q clean package`: exit 0, 183 tests, no failures/errors/skips.
- `mvn -q clean -DskipTests install`: exit 0; Maven's shaded-JAR integration checks also pass.
- Actual Auth integration: compile exit 0, JUnit exit 0, 3 tests, no skips.
- Runtime mutants: 14 named narrowing controls, each Maven exit 1 with its named assertion failure.
- Staged Auth foreign-A5 control: compile exit 0, JUnit exit 1 with two named assertion failures.
- Staged Auth issuer-B5 control: compile exit 0, JUnit exit 1; the named test expected 6982 and observed 9000.

Two clean builds and the installed local Maven artifact have identical SHA-256:
`84a5a2f27dbdd82724a40c34bb0b1a2c35ad73ab887f6b6c55b2d75f9c712d21`.
