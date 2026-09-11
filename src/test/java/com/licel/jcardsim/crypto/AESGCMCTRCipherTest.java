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
import javacard.security.KeyBuilder;
import javacardx.crypto.AEADCipher;
import javacardx.crypto.Cipher;
import junit.framework.TestCase;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * Contract tests for <code>AEADCipher.ALG_AES_GCM</code> and
 * <code>Cipher.ALG_AES_CTR</code>. Every row is driven through the production
 * entry point <code>Cipher.getInstance(byte, boolean)</code> (injected into the
 * Java Card API from <code>CipherProxy.getInstance</code>), which returns
 * <code>AEADCipherImpl</code> / <code>AESCTRCipherImpl</code>.
 */
public class AESGCMCTRCipherTest extends TestCase {

    // NIST GCM spec (SP 800-38D reference implementation) test case 4 / 16
    static final String GCM_PT = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
    static final String GCM_AAD = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
    static final String GCM_IV = "cafebabefacedbaddecaf888";
    static final String GCM_KEY_128 = "feffe9928665731c6d6a8f9467308308";
    static final String GCM_CT_128 = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091";
    static final String GCM_TAG_128 = "5bc94fbc3221a5db94fae95ae7121a47";
    static final String GCM_KEY_256 = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
    static final String GCM_CT_256 = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662";
    static final String GCM_TAG_256 = "76fc6ece0f4e1768cddf8853bb2d551b";

    // NIST SP 800-38A F.5.1 / F.5.3 / F.5.5 (CTR-AES128 / 192 / 256)
    static final String CTR_PT = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
    static final String CTR_IV = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    static final String CTR_KEY_128 = "2b7e151628aed2a6abf7158809cf4f3c";
    static final String CTR_CT_128 = "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee";
    static final String CTR_KEY_192 = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
    static final String CTR_CT_192 = "1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050";
    static final String CTR_KEY_256 = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    static final String CTR_CT_256 = "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6";

    public AESGCMCTRCipherTest(String testName) {
        super(testName);
    }

    // ---- GCM: NIST vectors ------------------------------------------------

    // Proves: GCM-128 encrypt via plain init(12-byte IV)+updateAAD+doFinal
    // outputs ONLY the NIST TC4 ciphertext (length == plaintext length),
    // retrieveTag returns the TC4 tag separately, and decrypt of the bare
    // ciphertext yields the plaintext with verifyTag true.
    public void testGcm128NistVector() {
        assertGcmVector(KeyBuilder.LENGTH_AES_128, GCM_KEY_128, GCM_CT_128, GCM_TAG_128);
    }

    // Proves: same contract for a 256-bit key against NIST TC16.
    public void testGcm256NistVector() {
        assertGcmVector(KeyBuilder.LENGTH_AES_256, GCM_KEY_256, GCM_CT_256, GCM_TAG_256);
    }

    // Proves: the AEAD init (explicit nonce/adataLen/messageLen/tagSize) and a
    // chunked update/doFinal sequence produce the same NIST TC4 ciphertext and
    // tag as the one-shot form (streaming does not change keystream or tag),
    // and the output buffer sized exactly to the plaintext is enough.
    public void testGcmAeadInitStreamingMatchesVector() {
        byte[] pt = Hex.decode(GCM_PT);
        byte[] aad = Hex.decode(GCM_AAD);
        byte[] iv = Hex.decode(GCM_IV);
        AEADCipher gcm = (AEADCipher) Cipher.getInstance(AEADCipher.ALG_AES_GCM, false);
        gcm.init(aesKey(KeyBuilder.LENGTH_AES_128, GCM_KEY_128), Cipher.MODE_ENCRYPT,
                iv, (short) 0, (short) iv.length, (short) aad.length, (short) pt.length, (short) 16);
        gcm.updateAAD(aad, (short) 0, (short) 7);
        gcm.updateAAD(aad, (short) 7, (short) (aad.length - 7));
        byte[] out = new byte[pt.length];
        short n = gcm.update(pt, (short) 0, (short) 5, out, (short) 0);
        n += gcm.update(pt, (short) 5, (short) 30, out, n);
        n += gcm.doFinal(pt, (short) 35, (short) (pt.length - 35), out, n);
        assertEquals(pt.length, n);
        assertEquals(GCM_CT_128, hex(out));
        byte[] tag = new byte[16];
        assertEquals(16, gcm.retrieveTag(tag, (short) 0, (short) 16));
        assertEquals(GCM_TAG_128, hex(tag));

        // chunked decrypt of the bare ciphertext: exactly pt.length bytes out
        byte[] ct = Hex.decode(GCM_CT_128);
        gcm.init(aesKey(KeyBuilder.LENGTH_AES_128, GCM_KEY_128), Cipher.MODE_DECRYPT, iv, (short) 0, (short) iv.length);
        gcm.updateAAD(aad, (short) 0, (short) aad.length);
        byte[] back = new byte[ct.length];
        short m = gcm.update(ct, (short) 0, (short) 20, back, (short) 0);
        m += gcm.update(ct, (short) 20, (short) 3, back, m);
        m += gcm.doFinal(ct, (short) 23, (short) (ct.length - 23), back, m);
        assertEquals(ct.length, m);
        assertEquals(GCM_PT, hex(back));
        assertTrue(gcm.verifyTag(tag, (short) 0, (short) 16, (short) 16));
    }

    // Proves: AAD is honoured — omitting the AAD changes the tag but not the
    // ciphertext (the expected tag for TC4 is bound to its AAD).
    public void testGcmAadChangesTagOnly() {
        byte[] pt = Hex.decode(GCM_PT);
        byte[] iv = Hex.decode(GCM_IV);
        AEADCipher gcm = (AEADCipher) Cipher.getInstance(AEADCipher.ALG_AES_GCM, false);
        gcm.init(aesKey(KeyBuilder.LENGTH_AES_128, GCM_KEY_128), Cipher.MODE_ENCRYPT, iv, (short) 0, (short) iv.length);
        byte[] out = new byte[pt.length];
        assertEquals(pt.length, gcm.doFinal(pt, (short) 0, (short) pt.length, out, (short) 0));
        assertEquals(GCM_CT_128, hex(out));
        byte[] tag = new byte[16];
        gcm.retrieveTag(tag, (short) 0, (short) 16);
        assertFalse(GCM_TAG_128.equals(hex(tag)));
    }

    // Proves: GCM-192 round-trips (no NIST vector with AAD pinned; positive control
    // for the 192-bit key path only).
    public void testGcm192RoundTrip() {
        byte[] key = Hex.decode("feffe9928665731c6d6a8f9467308308feffe9928665731c");
        byte[] pt = Hex.decode(GCM_PT);
        byte[] aad = Hex.decode(GCM_AAD);
        byte[] iv = Hex.decode(GCM_IV);
        SymmetricKeyImpl k = new SymmetricKeyImpl(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_192);
        k.setKey(key, (short) 0);
        AEADCipher gcm = (AEADCipher) Cipher.getInstance(AEADCipher.ALG_AES_GCM, false);
        gcm.init(k, Cipher.MODE_ENCRYPT, iv, (short) 0, (short) iv.length);
        gcm.updateAAD(aad, (short) 0, (short) aad.length);
        byte[] ct = new byte[pt.length];
        assertEquals(pt.length, gcm.doFinal(pt, (short) 0, (short) pt.length, ct, (short) 0));
        byte[] tag = new byte[16];
        gcm.retrieveTag(tag, (short) 0, (short) 16);
        gcm.init(k, Cipher.MODE_DECRYPT, iv, (short) 0, (short) iv.length);
        gcm.updateAAD(aad, (short) 0, (short) aad.length);
        byte[] back = new byte[pt.length];
        assertEquals(pt.length, gcm.doFinal(ct, (short) 0, (short) ct.length, back, (short) 0));
        assertTrue(Arrays.areEqual(pt, back));
        assertTrue(gcm.verifyTag(tag, (short) 0, (short) 16, (short) 16));
    }

    // Proves: the exact keyvault-crypto-lib sequence (CryptoPrimitives
    // probeAes256Gcm / sealGcm / openGcm) passes end to end on AES-256:
    // init(12-byte nonce) / updateAAD / doFinal(1 byte) == 1 / retrieveTag == 16 /
    // decrypt doFinal(1 byte) == 1 / verifyTag true / flipped tag byte ->
    // verifyTag false with no exception.
    public void testGcmKeyvaultWitnessSequence() {
        SymmetricKeyImpl key = aesKey(KeyBuilder.LENGTH_AES_256, GCM_KEY_256);
        byte[] nonce = Hex.decode(GCM_IV);
        byte[] aad = Hex.decode(GCM_AAD);
        byte[] pt = new byte[] { 0x42 };
        AEADCipher gcm = (AEADCipher) Cipher.getInstance(AEADCipher.ALG_AES_GCM, false);

        gcm.init(key, Cipher.MODE_ENCRYPT, nonce, (short) 0, (short) 12);
        gcm.updateAAD(aad, (short) 0, (short) aad.length);
        byte[] ct = new byte[1];
        assertEquals(1, gcm.doFinal(pt, (short) 0, (short) 1, ct, (short) 0));
        byte[] tag = new byte[16];
        assertEquals(16, gcm.retrieveTag(tag, (short) 0, (short) 16));
        assertFalse(Arrays.areEqual(pt, ct));

        gcm.init(key, Cipher.MODE_DECRYPT, nonce, (short) 0, (short) 12);
        gcm.updateAAD(aad, (short) 0, (short) aad.length);
        byte[] back = new byte[1];
        assertEquals(1, gcm.doFinal(ct, (short) 0, (short) 1, back, (short) 0));
        assertEquals(pt[0], back[0]);
        assertTrue(gcm.verifyTag(tag, (short) 0, (short) 16, (short) 16));

        byte[] flipped = Arrays.clone(tag);
        flipped[5] ^= 0x01;
        gcm.init(key, Cipher.MODE_DECRYPT, nonce, (short) 0, (short) 12);
        gcm.updateAAD(aad, (short) 0, (short) aad.length);
        assertEquals(1, gcm.doFinal(ct, (short) 0, (short) 1, back, (short) 0));
        assertFalse(gcm.verifyTag(flipped, (short) 0, (short) 16, (short) 16));
    }

    // ---- GCM: negative rows ------------------------------------------------

    // Proves: MODE_DECRYPT doFinal returns the plaintext WITHOUT verifying, and
    // a tag with one flipped bit (each of the 16 byte positions, including the
    // last one) is reported by verifyTag as false — no exception. Positive
    // control in the same setup: the unmodified tag verifies true.
    public void testGcmWrongTagVerifyFalseNoException() {
        byte[] ct = Hex.decode(GCM_CT_128);
        byte[] tag = Hex.decode(GCM_TAG_128);
        byte[] aad = Hex.decode(GCM_AAD);
        byte[] iv = Hex.decode(GCM_IV);
        SymmetricKeyImpl key = aesKey(KeyBuilder.LENGTH_AES_128, GCM_KEY_128);
        AEADCipher gcm = (AEADCipher) Cipher.getInstance(AEADCipher.ALG_AES_GCM, false);
        gcm.init(key, Cipher.MODE_DECRYPT, iv, (short) 0, (short) iv.length);
        gcm.updateAAD(aad, (short) 0, (short) aad.length);
        byte[] out = new byte[ct.length];
        assertEquals(ct.length, gcm.doFinal(ct, (short) 0, (short) ct.length, out, (short) 0));
        assertEquals(GCM_PT, hex(out));
        assertTrue(gcm.verifyTag(tag, (short) 0, (short) 16, (short) 16));
        for (int i = 0; i < 16; i++) {
            byte[] wrong = Arrays.clone(tag);
            wrong[i] ^= 0x01;
            assertFalse("flipped tag byte " + i + " accepted", gcm.verifyTag(wrong, (short) 0, (short) 16, (short) 16));
        }
        // still verifiable after the false verdicts, and a tag shorter than
        // required is false rather than an error
        assertTrue(gcm.verifyTag(tag, (short) 0, (short) 16, (short) 16));
        assertFalse(gcm.verifyTag(tag, (short) 0, (short) 15, (short) 16));
    }

    // Proves: wrong AAD on decrypt yields the same plaintext bytes (GCM is a
    // stream) but verifyTag false, without an exception.
    public void testGcmWrongAadVerifyFalse() {
        byte[] ct = Hex.decode(GCM_CT_128);
        byte[] tag = Hex.decode(GCM_TAG_128);
        byte[] aad = Hex.decode(GCM_AAD);
        byte[] iv = Hex.decode(GCM_IV);
        AEADCipher gcm = (AEADCipher) Cipher.getInstance(AEADCipher.ALG_AES_GCM, false);
        gcm.init(aesKey(KeyBuilder.LENGTH_AES_128, GCM_KEY_128), Cipher.MODE_DECRYPT, iv, (short) 0, (short) iv.length);
        gcm.updateAAD(aad, (short) 0, (short) (aad.length - 1));
        byte[] out = new byte[ct.length];
        assertEquals(ct.length, gcm.doFinal(ct, (short) 0, (short) ct.length, out, (short) 0));
        assertEquals(GCM_PT, hex(out));
        assertFalse(gcm.verifyTag(tag, (short) 0, (short) 16, (short) 16));
    }

    // Proves: verifyTag before doFinal and in encrypt mode -> ILLEGAL_USE;
    // retrieveTag before doFinal and in decrypt mode -> ILLEGAL_USE; an
    // unsupported tag length on either (17, 3, or != the configured size for
    // retrieveTag) -> ILLEGAL_VALUE; a 12-byte tag configured via the AEAD init
    // is retrieved as the leading 12 bytes of the TC4 tag.
    public void testGcmVerifyAndRetrieveTagState() {
        final byte[] ct = Hex.decode(GCM_CT_128);
        final byte[] tag = Hex.decode(GCM_TAG_128);
        final byte[] aad = Hex.decode(GCM_AAD);
        final byte[] iv = Hex.decode(GCM_IV);
        final byte[] pt = Hex.decode(GCM_PT);
        final AEADCipher gcm = (AEADCipher) Cipher.getInstance(AEADCipher.ALG_AES_GCM, false);
        gcm.init(aesKey(KeyBuilder.LENGTH_AES_128, GCM_KEY_128), Cipher.MODE_DECRYPT, iv, (short) 0, (short) iv.length);
        gcm.updateAAD(aad, (short) 0, (short) aad.length);
        assertReason(CryptoException.ILLEGAL_USE, new Runnable() {
            public void run() { gcm.verifyTag(tag, (short) 0, (short) 16, (short) 16); }
        });
        final byte[] out = new byte[ct.length];
        gcm.update(ct, (short) 0, (short) 8, out, (short) 0);
        assertReason(CryptoException.ILLEGAL_USE, new Runnable() {
            public void run() { gcm.verifyTag(tag, (short) 0, (short) 16, (short) 16); }
        });
        gcm.doFinal(ct, (short) 8, (short) (ct.length - 8), out, (short) 0);
        assertReason(CryptoException.ILLEGAL_USE, new Runnable() {
            public void run() { gcm.retrieveTag(out, (short) 0, (short) 16); }
        });
        assertReason(CryptoException.ILLEGAL_VALUE, new Runnable() {
            public void run() { gcm.verifyTag(tag, (short) 0, (short) 16, (short) 17); }
        });
        assertReason(CryptoException.ILLEGAL_VALUE, new Runnable() {
            public void run() { gcm.verifyTag(tag, (short) 0, (short) 16, (short) 3); }
        });
        assertTrue(gcm.verifyTag(tag, (short) 0, (short) 16, (short) 12));

        gcm.init(aesKey(KeyBuilder.LENGTH_AES_128, GCM_KEY_128), Cipher.MODE_ENCRYPT, iv, (short) 0, (short) iv.length);
        assertReason(CryptoException.ILLEGAL_USE, new Runnable() {
            public void run() { gcm.retrieveTag(out, (short) 0, (short) 16); }
        });
        gcm.doFinal(out, (short) 0, (short) 0, out, (short) 0);
        assertReason(CryptoException.ILLEGAL_USE, new Runnable() {
            public void run() { gcm.verifyTag(tag, (short) 0, (short) 16, (short) 16); }
        });
        assertReason(CryptoException.ILLEGAL_VALUE, new Runnable() {
            public void run() { gcm.retrieveTag(out, (short) 0, (short) 12); }
        });

        gcm.init(aesKey(KeyBuilder.LENGTH_AES_128, GCM_KEY_128), Cipher.MODE_ENCRYPT,
                iv, (short) 0, (short) iv.length, (short) aad.length, (short) pt.length, (short) 12);
        gcm.updateAAD(aad, (short) 0, (short) aad.length);
        gcm.doFinal(pt, (short) 0, (short) pt.length, out, (short) 0);
        byte[] short12 = new byte[12];
        assertEquals(12, gcm.retrieveTag(short12, (short) 0, (short) 12));
        assertEquals(GCM_TAG_128.substring(0, 24), hex(short12));
        assertReason(CryptoException.ILLEGAL_VALUE, new Runnable() {
            public void run() { gcm.retrieveTag(out, (short) 0, (short) 16); }
        });
    }

    // Proves: a DES key (wrong key type/size for AES-GCM) is refused with
    // ILLEGAL_VALUE; an AES key object with no key material is UNINITIALIZED_KEY;
    // a non-12-byte IV on the plain init is ILLEGAL_VALUE; an unsupported tag
    // size on the AEAD init is ILLEGAL_VALUE; init(Key, mode) uses a zero IV
    // (same ciphertext as an explicit 12 zero bytes).
    public void testGcmInitNegativeRows() {
        final byte[] iv = Hex.decode(GCM_IV);
        final AEADCipher gcm = (AEADCipher) Cipher.getInstance(AEADCipher.ALG_AES_GCM, false);
        final SymmetricKeyImpl des = new SymmetricKeyImpl(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES);
        des.setKey(Hex.decode("0123456789abcdef"), (short) 0);
        assertReason(CryptoException.ILLEGAL_VALUE, new Runnable() {
            public void run() { gcm.init(des, Cipher.MODE_ENCRYPT, iv, (short) 0, (short) iv.length); }
        });
        final SymmetricKeyImpl empty = new SymmetricKeyImpl(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128);
        assertReason(CryptoException.UNINITIALIZED_KEY, new Runnable() {
            public void run() { gcm.init(empty, Cipher.MODE_ENCRYPT, iv, (short) 0, (short) iv.length); }
        });
        final SymmetricKeyImpl key = aesKey(KeyBuilder.LENGTH_AES_128, GCM_KEY_128);
        assertReason(CryptoException.ILLEGAL_VALUE, new Runnable() {
            public void run() { gcm.init(key, Cipher.MODE_ENCRYPT, iv, (short) 0, (short) 11); }
        });
        assertReason(CryptoException.ILLEGAL_VALUE, new Runnable() {
            public void run() { gcm.init(key, Cipher.MODE_ENCRYPT, iv, (short) 0, (short) iv.length, (short) 0, (short) 0, (short) 3); }
        });
        // every failed init leaves the engine unusable
        assertReason(CryptoException.INVALID_INIT, new Runnable() {
            public void run() { gcm.doFinal(iv, (short) 0, (short) 0, iv, (short) 0); }
        });

        byte[] pt = Hex.decode(GCM_PT);
        gcm.init(key, Cipher.MODE_ENCRYPT);
        byte[] a = new byte[pt.length];
        gcm.doFinal(pt, (short) 0, (short) pt.length, a, (short) 0);
        gcm.init(key, Cipher.MODE_ENCRYPT, new byte[12], (short) 0, (short) 12);
        byte[] b = new byte[pt.length];
        gcm.doFinal(pt, (short) 0, (short) pt.length, b, (short) 0);
        assertTrue(Arrays.areEqual(a, b));
    }

    // Proves: doFinal / update / updateAAD / retrieveTag / verifyTag on a
    // never-initialised GCM engine raise INVALID_INIT (the Cipher API's
    // documented reason for an uninitialised engine); updateAAD after the
    // first data byte is ILLEGAL_USE.
    public void testGcmUseBeforeInit() {
        final byte[] buf = new byte[32];
        final AEADCipher gcm = (AEADCipher) Cipher.getInstance(AEADCipher.ALG_AES_GCM, false);
        assertReason(CryptoException.INVALID_INIT, new Runnable() {
            public void run() { gcm.doFinal(buf, (short) 0, (short) 16, buf, (short) 0); }
        });
        assertReason(CryptoException.INVALID_INIT, new Runnable() {
            public void run() { gcm.update(buf, (short) 0, (short) 16, buf, (short) 0); }
        });
        assertReason(CryptoException.INVALID_INIT, new Runnable() {
            public void run() { gcm.updateAAD(buf, (short) 0, (short) 16); }
        });
        assertReason(CryptoException.INVALID_INIT, new Runnable() {
            public void run() { gcm.retrieveTag(buf, (short) 0, (short) 16); }
        });
        assertReason(CryptoException.INVALID_INIT, new Runnable() {
            public void run() { gcm.verifyTag(buf, (short) 0, (short) 16, (short) 16); }
        });
        gcm.init(aesKey(KeyBuilder.LENGTH_AES_128, GCM_KEY_128), Cipher.MODE_ENCRYPT, buf, (short) 0, (short) 12);
        gcm.update(buf, (short) 0, (short) 4, buf, (short) 0);
        assertReason(CryptoException.ILLEGAL_USE, new Runnable() {
            public void run() { gcm.updateAAD(buf, (short) 0, (short) 16); }
        });
    }

    // Proves: Cipher.getInstance(ALG_AES_GCM, true) yields a working AEADCipher
    // producing the same NIST TC4 ciphertext and tag as externalAccess=false
    // (patch 1 parity).
    public void testGcmExternalAccessParity() {
        Cipher shared = Cipher.getInstance(AEADCipher.ALG_AES_GCM, true);
        assertTrue(shared instanceof AEADCipher);
        byte[] pt = Hex.decode(GCM_PT);
        byte[] iv = Hex.decode(GCM_IV);
        byte[] aad = Hex.decode(GCM_AAD);
        AEADCipher gcm = (AEADCipher) shared;
        gcm.init(aesKey(KeyBuilder.LENGTH_AES_128, GCM_KEY_128), Cipher.MODE_ENCRYPT, iv, (short) 0, (short) iv.length);
        gcm.updateAAD(aad, (short) 0, (short) aad.length);
        byte[] out = new byte[pt.length];
        assertEquals(pt.length, gcm.doFinal(pt, (short) 0, (short) pt.length, out, (short) 0));
        assertEquals(GCM_CT_128, hex(out));
        byte[] tag = new byte[16];
        gcm.retrieveTag(tag, (short) 0, (short) 16);
        assertEquals(GCM_TAG_128, hex(tag));
    }

    // ---- CTR: NIST vectors ------------------------------------------------

    // Proves: CTR-AES128 one-shot doFinal over 4 blocks equals SP 800-38A F.5.1
    // (which requires the counter to advance per block) and decrypt restores PT.
    public void testCtr128NistVector() {
        assertCtrVector(KeyBuilder.LENGTH_AES_128, CTR_KEY_128, CTR_CT_128);
    }

    // Proves: CTR-AES192 matches F.5.3.
    public void testCtr192NistVector() {
        assertCtrVector(KeyBuilder.LENGTH_AES_192, CTR_KEY_192, CTR_CT_192);
    }

    // Proves: CTR-AES256 matches F.5.5.
    public void testCtr256NistVector() {
        assertCtrVector(KeyBuilder.LENGTH_AES_256, CTR_KEY_256, CTR_CT_256);
    }

    // Proves: CTR is a stream — non-block-aligned update chunks (5, 30, rest)
    // reproduce F.5.1 byte-for-byte and a 7-byte message needs no padding.
    public void testCtrStreamingAndNoPadding() {
        byte[] pt = Hex.decode(CTR_PT);
        byte[] iv = Hex.decode(CTR_IV);
        Cipher ctr = Cipher.getInstance(Cipher.ALG_AES_CTR, false);
        ctr.init(aesKey(KeyBuilder.LENGTH_AES_128, CTR_KEY_128), Cipher.MODE_ENCRYPT, iv, (short) 0, (short) iv.length);
        byte[] out = new byte[pt.length];
        short n = ctr.update(pt, (short) 0, (short) 5, out, (short) 0);
        n += ctr.update(pt, (short) 5, (short) 30, out, n);
        n += ctr.doFinal(pt, (short) 35, (short) (pt.length - 35), out, n);
        assertEquals(pt.length, n);
        assertEquals(CTR_CT_128, hex(out));

        ctr.init(aesKey(KeyBuilder.LENGTH_AES_128, CTR_KEY_128), Cipher.MODE_ENCRYPT, iv, (short) 0, (short) iv.length);
        byte[] shortOut = new byte[7];
        assertEquals(7, ctr.doFinal(pt, (short) 0, (short) 7, shortOut, (short) 0));
        assertEquals(CTR_CT_128.substring(0, 14), hex(shortOut));
    }

    // Proves: the counter block is a 128-bit big-endian integer — an IV of
    // ff..ff wraps to 00..00 for the second block, i.e. block 2 of the
    // keystream equals E_K(0^128), which is also block 1 for a zero IV.
    public void testCtrCounterWrapsAsBigEndian128() {
        byte[] zeros = new byte[32];
        byte[] allOnes = new byte[16];
        Arrays.fill(allOnes, (byte) 0xFF);
        Cipher ctr = Cipher.getInstance(Cipher.ALG_AES_CTR, false);
        ctr.init(aesKey(KeyBuilder.LENGTH_AES_128, CTR_KEY_128), Cipher.MODE_ENCRYPT, allOnes, (short) 0, (short) 16);
        byte[] fromOnes = new byte[32];
        ctr.doFinal(zeros, (short) 0, (short) 32, fromOnes, (short) 0);
        ctr.init(aesKey(KeyBuilder.LENGTH_AES_128, CTR_KEY_128), Cipher.MODE_ENCRYPT, new byte[16], (short) 0, (short) 16);
        byte[] fromZero = new byte[16];
        ctr.doFinal(zeros, (short) 0, (short) 16, fromZero, (short) 0);
        assertTrue(Arrays.areEqual(fromZero, slice(fromOnes, 16, 32)));
        assertFalse(Arrays.areEqual(fromZero, slice(fromOnes, 0, 16)));
    }

    // ---- CTR: negative rows -------------------------------------------------

    // Proves: DES key -> ILLEGAL_VALUE; empty AES key -> UNINITIALIZED_KEY;
    // IV length other than 16 -> ILLEGAL_VALUE; doFinal/update before init ->
    // INVALID_INIT; doFinal consumes the init so a second doFinal is INVALID_INIT.
    public void testCtrNegativeRows() {
        final byte[] iv = Hex.decode(CTR_IV);
        final byte[] buf = new byte[32];
        final Cipher ctr = Cipher.getInstance(Cipher.ALG_AES_CTR, false);
        assertReason(CryptoException.INVALID_INIT, new Runnable() {
            public void run() { ctr.doFinal(buf, (short) 0, (short) 16, buf, (short) 0); }
        });
        assertReason(CryptoException.INVALID_INIT, new Runnable() {
            public void run() { ctr.update(buf, (short) 0, (short) 16, buf, (short) 0); }
        });
        final SymmetricKeyImpl des = new SymmetricKeyImpl(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES);
        des.setKey(Hex.decode("0123456789abcdef"), (short) 0);
        assertReason(CryptoException.ILLEGAL_VALUE, new Runnable() {
            public void run() { ctr.init(des, Cipher.MODE_ENCRYPT, iv, (short) 0, (short) 16); }
        });
        final SymmetricKeyImpl empty = new SymmetricKeyImpl(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256);
        assertReason(CryptoException.UNINITIALIZED_KEY, new Runnable() {
            public void run() { ctr.init(empty, Cipher.MODE_ENCRYPT, iv, (short) 0, (short) 16); }
        });
        final SymmetricKeyImpl key = aesKey(KeyBuilder.LENGTH_AES_128, CTR_KEY_128);
        assertReason(CryptoException.ILLEGAL_VALUE, new Runnable() {
            public void run() { ctr.init(key, Cipher.MODE_ENCRYPT, iv, (short) 0, (short) 12); }
        });
        assertReason(CryptoException.INVALID_INIT, new Runnable() {
            public void run() { ctr.doFinal(buf, (short) 0, (short) 16, buf, (short) 0); }
        });
    }

    // Proves: per the Cipher.doFinal contract, doFinal resets the cipher to
    // its initialized state (same IV/counter) instead of invalidating it, so
    // a second doFinal on the same vector after one init reproduces the same
    // ciphertext. Kills a mutant that fails to reset the counter block.
    public void testCtrDoFinalResetsForReuse() {
        byte[] pt = Hex.decode(CTR_PT);
        SymmetricKeyImpl key = aesKey(KeyBuilder.LENGTH_AES_128, CTR_KEY_128);
        byte[] iv = Hex.decode(CTR_IV);
        Cipher ctr = Cipher.getInstance(Cipher.ALG_AES_CTR, false);

        ctr.init(key, Cipher.MODE_ENCRYPT, iv, (short) 0, (short) iv.length);
        byte[] first = new byte[pt.length];
        ctr.doFinal(pt, (short) 0, (short) pt.length, first, (short) 0);
        assertEquals(CTR_CT_128, hex(first));

        byte[] second = new byte[pt.length];
        ctr.doFinal(pt, (short) 0, (short) pt.length, second, (short) 0);
        assertEquals(CTR_CT_128, hex(second));
        assertTrue(Arrays.areEqual(first, second));

        // split across update+doFinal, then doFinal a third time: still identical
        byte[] third = new byte[pt.length];
        short half = (short) (pt.length / 2);
        short produced = ctr.update(pt, (short) 0, half, third, (short) 0);
        ctr.doFinal(pt, half, (short) (pt.length - half), third, produced);
        assertEquals(CTR_CT_128, hex(third));
        assertTrue(Arrays.areEqual(first, third));
    }

    // Proves: Cipher.getInstance(ALG_AES_CTR, true) works and matches F.5.1.
    public void testCtrExternalAccessParity() {
        Cipher ctr = Cipher.getInstance(Cipher.ALG_AES_CTR, true);
        byte[] pt = Hex.decode(CTR_PT);
        byte[] iv = Hex.decode(CTR_IV);
        ctr.init(aesKey(KeyBuilder.LENGTH_AES_128, CTR_KEY_128), Cipher.MODE_ENCRYPT, iv, (short) 0, (short) iv.length);
        byte[] out = new byte[pt.length];
        ctr.doFinal(pt, (short) 0, (short) pt.length, out, (short) 0);
        assertEquals(CTR_CT_128, hex(out));
    }

    // Proves: init(Key, mode) without an IV uses the all-zero counter block
    // (same output as an explicit zero IV) instead of failing.
    public void testCtrInitWithoutIvUsesZeroCounter() {
        byte[] pt = Hex.decode(CTR_PT);
        Cipher ctr = Cipher.getInstance(Cipher.ALG_AES_CTR, false);
        ctr.init(aesKey(KeyBuilder.LENGTH_AES_128, CTR_KEY_128), Cipher.MODE_ENCRYPT);
        byte[] a = new byte[pt.length];
        ctr.doFinal(pt, (short) 0, (short) pt.length, a, (short) 0);
        ctr.init(aesKey(KeyBuilder.LENGTH_AES_128, CTR_KEY_128), Cipher.MODE_ENCRYPT, new byte[16], (short) 0, (short) 16);
        byte[] b = new byte[pt.length];
        ctr.doFinal(pt, (short) 0, (short) pt.length, b, (short) 0);
        assertTrue(Arrays.areEqual(a, b));
    }

    // ---- helpers -----------------------------------------------------------

    private void assertGcmVector(short keyBits, String keyHex, String ctHex, String tagHex) {
        byte[] pt = Hex.decode(GCM_PT);
        byte[] aad = Hex.decode(GCM_AAD);
        byte[] iv = Hex.decode(GCM_IV);
        SymmetricKeyImpl key = aesKey(keyBits, keyHex);
        AEADCipher gcm = (AEADCipher) Cipher.getInstance(AEADCipher.ALG_AES_GCM, false);

        gcm.init(key, Cipher.MODE_ENCRYPT, iv, (short) 0, (short) iv.length);
        gcm.updateAAD(aad, (short) 0, (short) aad.length);
        byte[] out = new byte[pt.length];
        assertEquals(pt.length, gcm.doFinal(pt, (short) 0, (short) pt.length, out, (short) 0));
        assertEquals(ctHex, hex(out));
        byte[] tag = new byte[16];
        assertEquals(16, gcm.retrieveTag(tag, (short) 0, (short) 16));
        assertEquals(tagHex, hex(tag));

        gcm.init(key, Cipher.MODE_DECRYPT, iv, (short) 0, (short) iv.length);
        gcm.updateAAD(aad, (short) 0, (short) aad.length);
        byte[] back = new byte[pt.length];
        assertEquals(pt.length, gcm.doFinal(out, (short) 0, (short) out.length, back, (short) 0));
        assertEquals(GCM_PT, hex(back));
        assertTrue(gcm.verifyTag(tag, (short) 0, (short) 16, (short) 16));
    }

    private void assertCtrVector(short keyBits, String keyHex, String ctHex) {
        byte[] pt = Hex.decode(CTR_PT);
        byte[] iv = Hex.decode(CTR_IV);
        SymmetricKeyImpl key = aesKey(keyBits, keyHex);
        Cipher ctr = Cipher.getInstance(Cipher.ALG_AES_CTR, false);
        ctr.init(key, Cipher.MODE_ENCRYPT, iv, (short) 0, (short) iv.length);
        byte[] out = new byte[pt.length];
        assertEquals(pt.length, ctr.doFinal(pt, (short) 0, (short) pt.length, out, (short) 0));
        assertEquals(ctHex, hex(out));
        ctr.init(key, Cipher.MODE_DECRYPT, iv, (short) 0, (short) iv.length);
        byte[] back = new byte[pt.length];
        assertEquals(pt.length, ctr.doFinal(out, (short) 0, (short) out.length, back, (short) 0));
        assertEquals(CTR_PT, hex(back));
    }

    // BC 1.46 lacks Hex.toHexString / Arrays.copyOfRange
    static String hex(byte[] data) {
        return new String(Hex.encode(data));
    }

    static byte[] slice(byte[] data, int from, int to) {
        byte[] out = new byte[to - from];
        System.arraycopy(data, from, out, 0, out.length);
        return out;
    }

    static SymmetricKeyImpl aesKey(short bits, String hex) {
        SymmetricKeyImpl key = new SymmetricKeyImpl(KeyBuilder.TYPE_AES, bits);
        key.setKey(Hex.decode(hex), (short) 0);
        return key;
    }

    static void assertReason(short reason, Runnable call) {
        try {
            call.run();
            fail("expected CryptoException " + reason);
        } catch (CryptoException e) {
            assertEquals(reason, e.getReason());
        }
    }
}
