/* SPDX-License-Identifier: Apache-2.0 */
package com.licel.jcardsim.crypto;

import java.util.Arrays;
import javacard.security.CryptoException;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.Signature;
import junit.framework.TestCase;

public class ECPublicPointValidationTest extends TestCase {
    public void testAgreementRejectsPointsOutsideTheCurve() {
        KeyPair pair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        pair.genKeyPair();
        KeyAgreement agreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        agreement.init(pair.getPrivate());
        byte[] valid = new byte[65];
        assertEquals(valid.length, ((ECPublicKey) pair.getPublic()).getW(valid, (short) 0));
        byte[] secret = new byte[32];
        assertEquals(secret.length, agreement.generateSecret(valid, (short) 0, (short) valid.length, secret, (short) 0));

        byte[] offCurve = new byte[65];
        offCurve[0] = 4;
        for (byte[] invalid : new byte[][] {offCurve, {0}, {4, 0}}) {
            Arrays.fill(secret, (byte) 0x5A);
            try {
                agreement.generateSecret(invalid, (short) 0, (short) invalid.length, secret, (short) 0);
                fail("Invalid point accepted");
            } catch (CryptoException refusal) {
                assertEquals(CryptoException.ILLEGAL_VALUE, refusal.getReason());
            }
            for (byte value : secret) {
                assertEquals(0x5A, value);
            }
        }
        assertEquals(secret.length, agreement.generateSecret(valid, (short) 0, (short) valid.length, secret, (short) 0));
    }

    public void testSignatureInitRejectsAnOffCurvePublicKey() {
        KeyPair pair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        pair.genKeyPair();
        ECPublicKey key = (ECPublicKey) pair.getPublic();
        Signature signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        signature.init(key, Signature.MODE_VERIFY);
        byte[] offCurve = new byte[65];
        offCurve[0] = 4;
        key.setW(offCurve, (short) 0, (short) offCurve.length);
        try {
            signature.init(key, Signature.MODE_VERIFY);
            fail("Invalid public key accepted");
        } catch (CryptoException refusal) {
            assertEquals(CryptoException.ILLEGAL_VALUE, refusal.getReason());
        }
    }
}
