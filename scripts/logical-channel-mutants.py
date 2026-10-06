#!/usr/bin/env python3
"""Run bounded narrowing mutants against the production APDU behavioral suite.

Java/JUnit remain the host test language. Python only applies one exact source
replacement, runs standalone Maven, checks its named assertion failure, and
restores the original bytes. Invoke serially with the host JVM lane free.
"""
import argparse
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = "src/main/java/com/licel/jcardsim/base/SimulatorRuntime.java"
MUTANTS = [
    ("unopened-2", RUNTIME, "if (!channelOpen[channel]) {", "if (!channelOpen[channel] && channel != 2) {", "testB6CannotReachBasicChannelSelection", "admits only unopened channel 2"),
    ("borrow-basic-on-2", RUNTIME, "currentAID = channelAIDs[channel];", "currentAID = channel == 2 && channelAIDs[channel] == null ? channelAIDs[0] : channelAIDs[channel];", "testOpenUnselectedChannelCannotBorrowSelection", "borrows basic selection only for unselected channel 2"),
    ("closed-2-open", RUNTIME, "channelOpen[target] = false;", "channelOpen[target] = target == 2;", "testCloseAndReopenNeverRestoresSelection", "leaves only closed channel 2 open"),
    ("ff-write", RUNTIME, "if (cla == (byte) 0xFF) {", "if (cla == (byte) 0xFF && command[ISO7816.OFFSET_INS] != 1) {", "testReservedFFDoesNotReachSelectedChannel19", "admits reserved FF only for state-writing INS 01"),
    ("duplicate-1", RUNTIME, "channelOpen[p2]) {", "(channelOpen[p2] && p2 != 1)) {", "testManageChannelRejectsInvalidTargetsWithoutChangingState", "admits duplicate open only on channel 1"),
    ("basic-close-00", RUNTIME, "if (target == 0) {", "if (target == 0 && cla != 0) {", "testManageChannelRejectsInvalidTargetsWithoutChangingState", "admits basic-channel close only for CLA 00"),
    ("close-target-20", RUNTIME, "final byte target = p2 == 0 ? origin : p2;", "final byte target = p2 == 20 ? 1 : (p2 == 0 ? origin : p2);", "testManageChannelRejectsInvalidTargetsWithoutChangingState", "aliases invalid close target 20 to valid target 1; range gate remains"),
    ("open-p1-01", RUNTIME, "if (p1 == 0x00) {", "if (p1 == 0x00 || p1 == 0x01) {", "testManageChannelRejectsInvalidTargetsWithoutChangingState", "admits open P1 01 only; all other invalid P1 remain refused"),
    ("sm-0c", RUNTIME, "if (secureMessaging) {", "if (secureMessaging && cla != 0x0C) {", "testManageChannelRejectsUnsupportedFraming", "admits only SM class 0C"),
    ("chaining-10", RUNTIME, "if (chaining) {", "if (chaining && cla != 0x10) {", "testManageChannelRejectsUnsupportedFraming", "admits only chained class 10"),
    ("data-open-1", RUNTIME, "apduCase == ApduCase.Case3 ||", "(apduCase == ApduCase.Case3 && p2 != 1) ||", "testManageChannelRejectsUnsupportedFraming", "admits only Case3 open of channel 1 through both framing checks"),
    ("single-on-1", RUNTIME, "alreadyActive = isActiveOnOtherChannel(newAid, channel);", "alreadyActive = channel != 1 && isActiveOnOtherChannel(newAid, channel);", "testNonMultiselectableSecondSelectionIsRejected", "admits a second non-MultiSelectable selection only on channel 1"),
    ("failed-select-1", RUNTIME, "if (!success) {", "if (!success && channel != 1) {", "testFailedSelectLeavesChannelUnselected", "admits refusing select callback only on channel 1"),
    ("cod-other-owner", "src/main/java/com/licel/jcardsim/base/TransientMemory.java", "arrayOwner == null || arrayOwner == owner", "arrayOwner == null || (arrayOwner instanceof javacard.framework.AID && ((javacard.framework.AID) arrayOwner).equals(new byte[]{(byte) 0xF0, 0, 0, 0, 2, 1}, (short) 0, (byte) 6)) || arrayOwner == owner", "testDeselectDoesNotClearAnotherChannelsTransientState", "also clears arrays owned by only fixture applet F00000000201"),
]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", choices=[m[0] for m in MUTANTS])
    parser.add_argument("--output", type=Path, default=ROOT / ".temp/logical-channel-mutants")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    results = []
    for name, filename, before, after, test, narrowing in MUTANTS:
        if args.only and name != args.only:
            continue
        source = ROOT / filename
        original = source.read_bytes()
        text = original.decode()
        if text.count(before) != 1:
            raise RuntimeError("replacement is not unique: " + name)
        report = ROOT / "target/surefire-reports/TEST-com.licel.jcardsim.base.LogicalChannelTest.xml"
        if report.exists():
            report.unlink()
        try:
            mutated = text.replace(before, after)
            if name == "data-open-1":
                framing = "if (apduCase != ApduCase.Case1) {\n                return sw(ISO7816.SW_WRONG_LENGTH);\n            }\n            if (p2 < 1"
                if mutated.count(framing) != 1:
                    raise RuntimeError("second framing replacement is not unique")
                mutated = mutated.replace(framing, "if (apduCase != ApduCase.Case1 && !(apduCase == ApduCase.Case3 && p2 == 1)) {\n                return sw(ISO7816.SW_WRONG_LENGTH);\n            }\n            if (p2 < 1")
            source.write_text(mutated)
            with (args.output / (name + ".log")).open("w") as log:
                run = subprocess.run(["mvn", "-q", "-Dtest=LogicalChannelTest", "test"], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, timeout=180)
            failed = []
            if report.exists():
                for case in ET.parse(report).getroot().iter("testcase"):
                    # An exception/setup error is not the intended assertion failure.
                    if case.find("failure") is not None:
                        failed.append(case.attrib["name"])
            killed = run.returncode != 0 and test in failed
            results.append({"mutant": name, "narrows": narrowing, "expectedTest": test, "failedTests": failed, "exitCode": run.returncode, "killed": killed})
            print(json.dumps(results[-1]), flush=True)
        finally:
            source.write_bytes(original)
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    # Survivors remain explicit evidence; this harness fails unless every mutant is killed.
    return 0 if all(r["killed"] for r in results) else 1

if __name__ == "__main__":
    raise SystemExit(main())
