/*
 * Copyright 2011 Licel LLC.
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

import java.math.BigInteger;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import junit.framework.TestCase;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.util.Arrays;

/**
 * Regression for the KeyAgreementImplTest random flake: ECPrivateKeyImpl.setParameters
 * must write the private scalar with the fixed field length, independent of the
 * scalar's own magnitude (BigInteger.toByteArray() length).
 */
public class ECPrivateKeyImplScalarLengthTest extends TestCase {

    private static final short FIELD_BYTES = 32;

    /**
     * Proves the flake mechanism deterministically: a short scalar written first sizes the
     * ByteContainer, and a full-length scalar written afterwards into the same key object
     * (what KeyPair.genKeyPair() does on reuse) must not overflow. Raw-toByteArray path
     * throws ArrayIndexOutOfBoundsException on the second setParameters.
     */
    public void testShortScalarThenFullLengthScalarOnSameKey() {
        ECPrivateKeyImpl key = (ECPrivateKeyImpl) KeyBuilder.buildKey(
                KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        ECDomainParameters dp = key.getDomainParameters();
        BigInteger full = dp.getN().subtract(BigInteger.ONE);
        assertEquals(33, full.toByteArray().length); // top bit set -> sign byte
        key.setParameters(new ECPrivateKeyParameters(BigInteger.ONE, dp));
        // raw-toByteArray path: ByteContainer sized to 1 byte here, AIOOBE on the next write
        key.setParameters(new ECPrivateKeyParameters(full, dp));
        byte[] s = new byte[64];
        assertEquals(FIELD_BYTES, key.getS(s, (short) 0));
        byte[] stored = new byte[FIELD_BYTES];
        System.arraycopy(s, 0, stored, 0, FIELD_BYTES);
        assertEquals(full, new BigInteger(1, stored));
    }

    /**
     * Proves a scalar with the top bit set (33-byte toByteArray for P-256) is stored with
     * the fixed 32-byte length, round-trips through getParameters, and agrees in ECDH
     * through the production KeyAgreement entry point.
     */
    public void testTopBitSetScalarSetsAndAgrees() {
        KeyPair kp = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        kp.genKeyPair();
        ECPrivateKeyImpl priv1 = (ECPrivateKeyImpl) kp.getPrivate();
        ECPublicKeyImpl pub1 = (ECPublicKeyImpl) kp.getPublic();
        ECDomainParameters dp = priv1.getDomainParameters();

        BigInteger d = dp.getN().subtract(BigInteger.valueOf(12345));
        assertTrue(d.testBit(255));
        assertEquals(33, d.toByteArray().length);
        priv1.setParameters(new ECPrivateKeyParameters(d, dp));
        pub1.setParameters(new ECPublicKeyParameters(dp.getG().multiply(d), dp));

        byte[] sBuf = new byte[64];
        assertEquals(FIELD_BYTES, priv1.getS(sBuf, (short) 0));
        assertEquals(d, ((ECPrivateKeyParameters) priv1.getParameters()).getD());

        KeyPair kp2 = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        kp2.genKeyPair();
        ECPrivateKey priv2 = (ECPrivateKey) kp2.getPrivate();
        ECPublicKey pub2 = (ECPublicKey) kp2.getPublic();

        KeyAgreement ka = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        byte[] w2 = new byte[128];
        short w2Len = pub2.getW(w2, (short) 0);
        byte[] secret1 = new byte[65];
        ka.init(priv1);
        short len1 = ka.generateSecret(w2, (short) 0, w2Len, secret1, (short) 0);

        byte[] w1 = new byte[128];
        short w1Len = pub1.getW(w1, (short) 0);
        byte[] secret2 = new byte[65];
        ka.init(priv2);
        short len2 = ka.generateSecret(w1, (short) 0, w1Len, secret2, (short) 0);

        assertEquals(len1, len2);
        assertTrue(Arrays.areEqual(secret1, secret2));
    }

    /** Negative bound of the helper: a scalar wider than the field length is refused, not truncated. */
    public void testScalarWiderThanFieldIsRejected() {
        try {
            ECPrivateKeyImpl.asUnsignedByteArray((short) 2, BigInteger.valueOf(0x10000));
            fail("expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
        }
        assertTrue(Arrays.areEqual(new byte[]{0, 1}, ECPrivateKeyImpl.asUnsignedByteArray((short) 2, BigInteger.ONE)));
    }
}
