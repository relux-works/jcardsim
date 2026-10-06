#!/usr/bin/env python3
"""Compile an unchanged, identified BSimID jc consumer against this runtime JAR.

Uses Java/JUnit 5 tests, the consumer's own simulator and released CAP payloads.
Python only stages identified inputs and invokes javac/JUnit as standalone
processes. Requires a free host JVM lane. Never runs a consumer build or writes
into the supplied BSimID/bridge checkout.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()
def verify_payload(cap, jar):
    with zipfile.ZipFile(cap) as archive, zipfile.ZipFile(jar) as payload:
        expected = {(n[len('APPLET-INF/classes/'):] if n.startswith('APPLET-INF/classes/') else n): archive.read(n)
                    for n in archive.namelist() if n.endswith('.class')}
        actual = {n: payload.read(n) for n in payload.namelist() if n.endswith('.class')}
        if not expected or expected != actual:
            raise RuntimeError('host classes do not match released CAP: '+str(jar))
def main():
    p = argparse.ArgumentParser()
    p.add_argument('--bsimid-root', type=Path, required=True)
    p.add_argument('--bridge-jar', type=Path, required=True)
    p.add_argument('--junit-home', type=Path, default=Path.home()/'.m2/repository')
    p.add_argument('--output', type=Path, default=ROOT/'.temp/bsimid-channel-integration')
    controls=p.add_mutually_exclusive_group()
    controls.add_argument('--narrow-foreign-a5', action='store_true', help='control: admit only foreign CLA A5 in actual Auth process()')
    controls.add_argument('--narrow-issuer-b5', action='store_true', help='control: admit only B5 56 without an issuer session')
    args = p.parse_args()
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=True)
    consumer = args.bsimid_root.resolve(); jc = consumer/'jc'
    jars = [ROOT/'target/jcardsim-3.0.5.9-relux.3.jar', args.bridge_jar.resolve()]
    lock = json.loads((consumer/'dependencies.lock.json').read_text())
    entries = {r['id']:r for r in lock['repositories']}
    for package in entries['keyvault-v5']['familyRelease']['packages']:
        basename = Path(package['capPath']).stem
        cap = jc/'.deps/keyvault-v5'/(basename+'.cap')
        if sha(cap) != package['capSha256']:
            raise RuntimeError('released CAP digest mismatch: '+str(cap))
        payload=jc/'.deps/keyvault-v5'/(basename+'-cap-classes.jar')
        verify_payload(cap,payload)
        jars.append(payload)
    receipt = json.loads((jc/'.deps/keyvault-crypto-lib/receipt.json').read_text())
    crypto = Path(receipt['capClassesJar'])
    if sha(crypto) != receipt['capClassesJarSha256']:
        raise RuntimeError('crypto library classes digest mismatch')
    crypto_cap=Path(receipt['cap'])
    if sha(crypto_cap) != receipt['capSha256']:
        raise RuntimeError('crypto CAP digest mismatch')
    verify_payload(crypto_cap,crypto)
    jars.append(crypto)
    for group, name, version in [
        ('org/junit/jupiter','junit-jupiter-api','5.11.4'),
        ('org/junit/jupiter','junit-jupiter-engine','5.11.4'),
        ('org/junit/platform','junit-platform-engine','1.11.4'),
        ('org/junit/platform','junit-platform-commons','1.11.4'),
        ('org/junit/platform','junit-platform-launcher','1.11.4'),
        ('org/opentest4j','opentest4j','1.3.0'),
        ('org/apiguardian','apiguardian-api','1.1.2')]:
        jars.append(args.junit_home/group/name/version/(name+'-'+version+'.jar'))
    inputs=[]; sources=[]
    for rel in ['jc/applets/auth/src/main/java', 'jc/generated/bsimauth-server-javacard/src/main/java', 'jc/simulator/src/main/java']:
        source_root=consumer/rel
        for source in sorted(source_root.rglob('*.java')):
            target=out/'inputs'/source.relative_to(consumer)
            target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(source,target)
            inputs.append({'source':str(source.relative_to(consumer)), 'sha256':sha(source)})
            sources.append(target)
    if args.narrow_foreign_a5:
        applet = out/'inputs/jc/applets/auth/src/main/java/ru/mts/bsimid/applet/auth/BSimAuthApplet.java'
        text=applet.read_text()
        before='if (!isAuthClass(buffer[ISO7816.OFFSET_CLA])) {'
        if text.count(before)!=1:
            raise RuntimeError('foreign-class control was not applied uniquely')
        applet.write_text(text.replace(before, 'if (!isAuthClass(buffer[ISO7816.OFFSET_CLA]) && buffer[ISO7816.OFFSET_CLA] != (byte) 0xA5) {'))
    if args.narrow_issuer_b5:
        applet = out/'inputs/jc/applets/auth/src/main/java/ru/mts/bsimid/applet/auth/BSimAuthApplet.java'
        text=applet.read_text()
        before='private short requireIssuerSession(byte[] buffer, short length) {\n        SecureChannel channel = GPSystem.getSecureChannel();\n        if (channel == null) {'
        if text.count(before)!=1:
            raise RuntimeError('issuer control was not applied uniquely')
        applet.write_text(text.replace(before, before+'\n            if (buffer[ISO7816.OFFSET_CLA] == (byte) 0xB5 && buffer[ISO7816.OFFSET_INS] == 0x56) return length;'))
    sources += sorted((ROOT/'integration/bsimid').glob('*.java'))
    cp=os.pathsep.join(str(j) for j in jars)
    classes=out/'classes'; classes.mkdir(exist_ok=True)
    java_home=Path(os.environ['JAVA_HOME'])
    identity={'bsimidCommit': subprocess.check_output(['git','-C',str(consumer),'rev-parse','HEAD'],text=True).strip(),
              'jcCommit': subprocess.check_output(['git','-C',str(jc),'rev-parse','HEAD'],text=True).strip(),
              'mutation': 'foreign-a5' if args.narrow_foreign_a5 else ('issuer-b5' if args.narrow_issuer_b5 else None),
              'inputs':inputs,'jars':[{'name':j.name,'sha256':sha(j)} for j in jars]}
    (out/'identity.json').write_text(json.dumps(identity,indent=2)+'\n')
    commands=[([str(java_home/'bin/javac'),'--release','17','-cp',cp,'-d',str(classes)]+[str(s) for s in sources],'compile.log'),
              ([str(java_home/'bin/java'),'-noverify','-cp',str(classes)+os.pathsep+cp,'RunTests'],'test.log')]
    for command, filename in commands:
        with (out/filename).open('w') as log:
            result=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,timeout=180)
        print(json.dumps({'command':command,'log':filename,'exitCode':result.returncode}),flush=True)
        if result.returncode: return result.returncode
    return 0
if __name__=='__main__': raise SystemExit(main())
