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

import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacardx.crypto.AEADCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;

/**
 * Implementation of <code>AEADCipher</code> for <code>ALG_AES_GCM</code> based
 * on the BouncyCastle <code>GCMBlockCipher</code>, following the Java Card
 * 3.0.5 <code>AEADCipher</code> contract:
 * <ul>
 * <li>MODE_ENCRYPT: <code>doFinal</code> outputs only the ciphertext (same
 * length as the plaintext); the tag is obtained afterwards with
 * <code>retrieveTag</code>.</li>
 * <li>MODE_DECRYPT: the input is the ciphertext without the tag,
 * <code>doFinal</code> outputs the plaintext without verifying anything; the
 * tag is checked afterwards with <code>verifyTag</code>, which returns
 * <code>false</code> on mismatch and never throws for a mismatch.</li>
 * <li><code>retrieveTag</code> / <code>verifyTag</code> before
 * <code>doFinal</code> (or in the wrong mode) raise <code>ILLEGAL_USE</code>;
 * an unsupported tag length raises <code>ILLEGAL_VALUE</code>.</li>
 * </ul>
 * The nonce is supplied through <code>init(Key, mode, bArray, ...)</code>
 * (12 bytes); <code>init(Key, mode)</code> uses an all-zero 12-byte IV as the
 * API documents. The offline-style 8-argument init is accepted as well, which
 * is the only way to select a tag size other than 16.
 * @see AEADCipher
 */
public class AEADCipherImpl extends AEADCipher {

    static final short DEFAULT_TAG_LENGTH = 16;
    static final short MIN_TAG_LENGTH = 4;
    static final short DEFAULT_NONCE_LENGTH = 12;

    byte algorithm;
    GCMBlockCipher engine;
    boolean isInitialized;
    boolean isEncrypt;
    boolean isFinalized;
    // true once the first message byte has been fed: AAD is closed after that
    boolean dataStarted;
    KeyParameter keyParameter;
    short tagLength;
    byte[] nonce;
    byte[] aad;
    // tag computed by the last doFinal (encrypt: to retrieve; decrypt: to verify)
    byte[] computedTag;
    // decrypt mode: BC holds back tagLength bytes of input, so the plaintext
    // emitted so far is tracked to size the flush in doFinal
    int inputTotal;
    int outputTotal;

    public AEADCipherImpl(byte algorithm) {
        this.algorithm = algorithm;
    }

    public void init(Key theKey, byte theMode) throws CryptoException {
        // API: "AEADCipher in GCM mode will use 0 for initial vector (IV)"
        init(theKey, theMode, new byte[DEFAULT_NONCE_LENGTH], (short) 0, DEFAULT_NONCE_LENGTH,
                (short) 0, (short) 0, DEFAULT_TAG_LENGTH);
    }

    public void init(Key theKey, byte theMode, byte[] bArray, short bOff, short bLen) throws CryptoException {
        if (bLen != DEFAULT_NONCE_LENGTH) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        init(theKey, theMode, bArray, bOff, bLen, (short) 0, (short) 0, DEFAULT_TAG_LENGTH);
    }

    public void init(Key theKey, byte theMode, byte[] nonceBuf, short nonceOff, short nonceLen, short adataLen, short messageLen, short tagSize) throws CryptoException {
        isInitialized = false;
        if (theMode != MODE_ENCRYPT && theMode != MODE_DECRYPT) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        if (nonceLen < 1 || adataLen < 0 || messageLen < 0 || !isSupportedTagLength(tagSize)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        tagLength = tagSize;
        keyParameter = selectKey(theKey);
        nonce = new byte[nonceLen];
        Util.arrayCopyNonAtomic(nonceBuf, nonceOff, nonce, (short) 0, nonceLen);
        aad = new byte[0];
        engine = new GCMBlockCipher(new AESEngine());
        isEncrypt = theMode == MODE_ENCRYPT;
        computedTag = null;
        resetState();
        isInitialized = true;
    }

    private void resetState() {
        engine.init(isEncrypt, new AEADParameters(keyParameter, tagLength * 8, nonce, aad));
        isFinalized = false;
        dataStarted = false;
        inputTotal = 0;
        outputTotal = 0;
    }

    public void updateAAD(byte[] aadBuf, short aadOff, short aadLen) throws CryptoException {
        checkInitialized();
        // BC 1.46 GCMBlockCipher accepts AAD only through AEADParameters, so
        // the engine is re-initialised with the extended AAD; the API forbids
        // AAD after the first message byte, which is what makes that sound.
        if (dataStarted) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
        byte[] merged = new byte[aad.length + aadLen];
        System.arraycopy(aad, 0, merged, 0, aad.length);
        Util.arrayCopyNonAtomic(aadBuf, aadOff, merged, (short) aad.length, aadLen);
        aad = merged;
        computedTag = null;
        resetState();
    }

    public short update(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) throws CryptoException {
        checkInitialized();
        if (inLength <= 0) {
            return 0;
        }
        dataStarted = true;
        return process(inBuff, inOffset, inLength, outBuff, outOffset);
    }

    public short doFinal(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) throws CryptoException {
        checkInitialized();
        dataStarted = true;
        short produced = process(inBuff, inOffset, inLength, outBuff, outOffset);
        try {
            if (isEncrypt) {
                // BC appends the tag to the output: finish into a scratch
                // buffer so only ciphertext reaches the caller
                byte[] tail = new byte[engine.getOutputSize(0)];
                int tailLen = engine.doFinal(tail, 0) - tagLength;
                Util.arrayCopyNonAtomic(tail, (short) 0, outBuff, (short) (outOffset + produced), (short) tailLen);
                Arrays.fill(tail, (byte) 0);
                produced += tailLen;
            } else {
                // BC's decrypt holds the trailing tagLength input bytes back as
                // the tag. The contract defers verification to verifyTag, so a
                // zero placeholder tag is appended to flush the real plaintext;
                // BC's own comparison against the placeholder is ignored and the
                // computed tag it leaves behind is kept for verifyTag.
                byte[] placeholder = new byte[tagLength];
                produced += process(placeholder, (short) 0, tagLength, outBuff, (short) (outOffset + produced));
                inputTotal -= tagLength;
                int remaining = inputTotal - outputTotal;
                try {
                    engine.doFinal(outBuff, outOffset + produced);
                } catch (InvalidCipherTextException expected) {
                    // placeholder tag mismatch: plaintext and tag are already computed
                }
                produced += remaining;
                outputTotal += remaining;
            }
            computedTag = engine.getMac();
        } catch (InvalidCipherTextException ex) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        } catch (IllegalStateException ex) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
        // the API resets the cipher to its post-init state after doFinal; the
        // tag of the finished operation stays retrievable/verifiable until the
        // next data byte or init
        byte[] tag = computedTag;
        resetState();
        computedTag = tag;
        isFinalized = true;
        return produced;
    }

    public short retrieveTag(byte[] tagBuf, short tagOff, short tagLen) throws CryptoException {
        checkInitialized();
        if (!isEncrypt || !isFinalized) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
        if (tagLen != tagLength) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        Util.arrayCopyNonAtomic(computedTag, (short) 0, tagBuf, tagOff, tagLen);
        return tagLen;
    }

    public boolean verifyTag(byte[] receivedTagBuf, short receivedTagOff, short receivedTagLen, short requiredTagLen) throws CryptoException {
        checkInitialized();
        if (isEncrypt || !isFinalized) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
        if (!isSupportedTagLength(requiredTagLen) || requiredTagLen > tagLength) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        if (receivedTagLen < requiredTagLen) {
            return false;
        }
        // constant-time compare of the leading requiredTagLen bytes
        int diff = 0;
        for (short i = 0; i < requiredTagLen; i++) {
            diff |= computedTag[i] ^ receivedTagBuf[(short) (receivedTagOff + i)];
        }
        return diff == 0;
    }

    public byte getAlgorithm() {
        return algorithm;
    }

    public byte getCipherAlgorithm() {
        return CIPHER_AES_GCM;
    }

    public byte getPaddingAlgorithm() {
        return PAD_NULL;
    }

    // NIST SP 800-38D: 128, 120, 112, 104, 96 bits, plus 64 and 32
    private static boolean isSupportedTagLength(short bytes) {
        return (bytes >= 12 && bytes <= 16) || bytes == 8 || bytes == MIN_TAG_LENGTH;
    }

    private short process(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) {
        if (isFinalized) {
            // data after doFinal starts a fresh operation with the same key/IV
            isFinalized = false;
            computedTag = null;
        }
        int n = engine.processBytes(inBuff, inOffset, inLength, outBuff, outOffset);
        inputTotal += inLength;
        outputTotal += n;
        return (short) n;
    }

    private KeyParameter selectKey(Key theKey) {
        if (theKey == null || !theKey.isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        if (!(theKey instanceof AESKey) || !(theKey instanceof SymmetricKeyImpl)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        short size = theKey.getSize();
        if (size != 128 && size != 192 && size != 256) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        return (KeyParameter) ((SymmetricKeyImpl) theKey).getParameters();
    }

    private void checkInitialized() {
        if (!isInitialized) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }
    }
}
