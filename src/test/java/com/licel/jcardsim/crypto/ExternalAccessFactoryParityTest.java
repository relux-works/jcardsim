/*
 * Copyright 2026 Licel LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.licel.jcardsim.crypto;

import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.InitializedMessageDigest;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.Signature;
import javacardx.crypto.Cipher;
import junit.framework.TestCase;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * Contract test for the <code>externalAccess</code> flag on the four engine
 * factories. The simulator has no CLEAR_ON_DESELECT / firewall-context
 * distinction for engine buffers, so <code>externalAccess=true</code> must be
 * accepted and behave exactly like <code>externalAccess=false</code>.
 *
 * Production call sites driven: MessageDigestProxy.getInstance(byte,boolean),
 * MessageDigestProxy.getInitializedMessageDigestInstance(byte,boolean),
 * CipherProxy.getInstance(byte,boolean), SignatureProxy.getInstance(byte,boolean),
 * KeyAgreementProxy.getInstance(byte,boolean) — all reached through the
 * injected javacard.security / javacardx.crypto API classes.
 */
public class ExternalAccessFactoryParityTest extends TestCase {

    static final String MESSAGE = "F9607F6E66B4162C";
    static final String MESSAGE_16 = "000102030405060708090A0B0C0D0E0F";
    static final String AES_KEY = "000102030405060708090A0B0C0D0E0F";
    // algorithm id outside every ALG_* table of every factory
    static final byte UNKNOWN_ALG = (byte) 0x7F;

    public ExternalAccessFactoryParityTest(String testName) {
        super(testName);
    }

    // Proves: MessageDigest.getInstance(ALG_SHA_256, true) returns a working
    // engine whose doFinal equals the externalAccess=false engine on a fixed vector.
    public void testMessageDigestExternalAccessParity() {
        MessageDigest shared = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, true);
        MessageDigest local = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        assertTrue(Arrays.areEqual(digest(local), digest(shared)));
    }

    // Proves: getInitializedMessageDigestInstance(ALG_SHA_256, true) returns a
    // working engine matching the externalAccess=false engine.
    public void testInitializedMessageDigestExternalAccessParity() {
        InitializedMessageDigest shared = MessageDigest.getInitializedMessageDigestInstance(MessageDigest.ALG_SHA_256, true);
        InitializedMessageDigest local = MessageDigest.getInitializedMessageDigestInstance(MessageDigest.ALG_SHA_256, false);
        assertTrue(Arrays.areEqual(digest(local), digest(shared)));
    }

    // Proves: Cipher.getInstance(ALG_AES_BLOCK_128_CBC_NOPAD, true) returns a
    // working engine producing the same ciphertext as the externalAccess=false engine.
    public void testCipherExternalAccessParity() {
        SymmetricKeyImpl key = new SymmetricKeyImpl(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128);
        key.setKey(Hex.decode(AES_KEY), (short) 0);
        Cipher shared = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, true);
        Cipher local = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        byte[] a = encrypt(local, key);
        byte[] b = encrypt(shared, key);
        assertEquals(16, a.length);
        assertTrue(Arrays.areEqual(a, b));
    }

    // Proves: Signature.getInstance(ALG_ECDSA_SHA_256, true) is accepted and
    // interoperates with the externalAccess=false engine in both directions
    // (ECDSA signatures are randomised, so cross-verification is the equality check).
    public void testSignatureExternalAccessParity() {
        KeyPair kp = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        kp.genKeyPair();
        Signature shared = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, true);
        Signature local = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        assertTrue(crossVerify(shared, local, kp));
        assertTrue(crossVerify(local, shared, kp));
    }

    // Proves: KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN, true) yields the same
    // shared secret as the externalAccess=false engine for a fixed key pair.
    public void testKeyAgreementExternalAccessParity() {
        KeyPair kp1 = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        kp1.genKeyPair();
        KeyPair kp2 = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        kp2.genKeyPair();
        KeyAgreement shared = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, true);
        KeyAgreement local = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        byte[] a = agree(local, kp1, kp2);
        byte[] b = agree(shared, kp1, kp2);
        assertTrue(a.length > 0);
        assertTrue(Arrays.areEqual(a, b));
    }

    // Negative control: an unknown algorithm still throws NO_SUCH_ALGORITHM for
    // both flag values on all four factories, so removing the externalAccess gate
    // did not widen algorithm coverage.
    public void testUnknownAlgorithmStillRejectedForBothFlags() {
        boolean[] flags = {false, true};
        for (int i = 0; i < flags.length; i++) {
            final boolean f = flags[i];
            assertNoSuchAlgorithm(new Runnable() {
                public void run() { MessageDigest.getInstance(UNKNOWN_ALG, f); }
            });
            assertNoSuchAlgorithm(new Runnable() {
                public void run() { MessageDigest.getInitializedMessageDigestInstance(UNKNOWN_ALG, f); }
            });
            assertNoSuchAlgorithm(new Runnable() {
                public void run() { Cipher.getInstance(UNKNOWN_ALG, f); }
            });
            assertNoSuchAlgorithm(new Runnable() {
                public void run() { Signature.getInstance(UNKNOWN_ALG, f); }
            });
            assertNoSuchAlgorithm(new Runnable() {
                public void run() { KeyAgreement.getInstance(UNKNOWN_ALG, f); }
            });
        }
    }

    private static void assertNoSuchAlgorithm(Runnable r) {
        try {
            r.run();
            fail("expected CryptoException.NO_SUCH_ALGORITHM");
        } catch (CryptoException e) {
            assertEquals(CryptoException.NO_SUCH_ALGORITHM, e.getReason());
        }
    }

    private static byte[] digest(MessageDigest md) {
        byte[] msg = Hex.decode(MESSAGE);
        byte[] out = new byte[md.getLength()];
        md.doFinal(msg, (short) 0, (short) msg.length, out, (short) 0);
        return out;
    }

    private static byte[] encrypt(Cipher c, SymmetricKeyImpl key) {
        byte[] msg = Hex.decode(MESSAGE_16);
        byte[] out = new byte[msg.length];
        c.init(key, Cipher.MODE_ENCRYPT);
        c.doFinal(msg, (short) 0, (short) msg.length, out, (short) 0);
        return out;
    }

    private static boolean crossVerify(Signature signer, Signature verifier, KeyPair kp) {
        byte[] msg = Hex.decode(MESSAGE);
        signer.init(kp.getPrivate(), Signature.MODE_SIGN);
        byte[] sig = new byte[signer.getLength()];
        short len = signer.sign(msg, (short) 0, (short) msg.length, sig, (short) 0);
        verifier.init(kp.getPublic(), Signature.MODE_VERIFY);
        return verifier.verify(msg, (short) 0, (short) msg.length, sig, (short) 0, len);
    }

    private static byte[] agree(KeyAgreement ka, KeyPair mine, KeyPair theirs) {
        ka.init((ECPrivateKey) mine.getPrivate());
        ECPublicKey pub = (ECPublicKey) theirs.getPublic();
        byte[] w = new byte[128];
        short wLen = pub.getW(w, (short) 0);
        byte[] secret = new byte[128];
        short len = ka.generateSecret(w, (short) 0, wLen, secret, (short) 0);
        return java.util.Arrays.copyOf(secret, len);
    }
}
