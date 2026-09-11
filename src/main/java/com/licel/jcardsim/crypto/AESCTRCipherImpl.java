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
import javacardx.crypto.Cipher;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Implementation of <code>Cipher.ALG_AES_CTR</code> (NIST SP 800-38A counter
 * mode) over the BouncyCastle <code>AESEngine</code>.
 * <p>
 * The counter block is the 16-byte IV incremented as a big-endian integer
 * after every keystream block. There is no padding; the stream position is
 * kept across <code>update</code> calls so arbitrary chunking is allowed.
 * @see Cipher
 */
public class AESCTRCipherImpl extends Cipher {

    static final short BLOCK_SIZE = 16;

    byte algorithm;
    BlockCipher engine;
    boolean isInitialized;
    byte[] counter;
    byte[] initialCounter;
    byte[] keyStream;
    // bytes of keyStream already consumed; BLOCK_SIZE means "generate next block"
    short keyStreamOffset;

    public AESCTRCipherImpl(byte algorithm) {
        this.algorithm = algorithm;
    }

    public void init(Key theKey, byte theMode) throws CryptoException {
        // default counter block per the Cipher API convention: all zero IV
        init(theKey, theMode, new byte[BLOCK_SIZE], (short) 0, BLOCK_SIZE);
    }

    public void init(Key theKey, byte theMode, byte[] bArray, short bOff, short bLen) throws CryptoException {
        if (theMode != MODE_ENCRYPT && theMode != MODE_DECRYPT) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        if (bLen != BLOCK_SIZE) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        KeyParameter keyParameter = selectKey(theKey);
        engine = new AESEngine();
        // CTR uses the forward cipher in both directions
        engine.init(true, keyParameter);
        counter = new byte[BLOCK_SIZE];
        Util.arrayCopyNonAtomic(bArray, bOff, counter, (short) 0, bLen);
        initialCounter = new byte[BLOCK_SIZE];
        Util.arrayCopyNonAtomic(counter, (short) 0, initialCounter, (short) 0, BLOCK_SIZE);
        keyStream = new byte[BLOCK_SIZE];
        keyStreamOffset = BLOCK_SIZE;
        isInitialized = true;
    }

    public byte getAlgorithm() {
        return algorithm;
    }

    public byte getCipherAlgorithm() {
        // 3.0.5 defines no CIPHER_AES_CTR constant; CTR is AES with no padding
        return CIPHER_AES_ECB;
    }

    public byte getPaddingAlgorithm() {
        return PAD_NOPAD;
    }

    public short update(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) throws CryptoException {
        if (!isInitialized) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }
        for (short i = 0; i < inLength; i++) {
            if (keyStreamOffset == BLOCK_SIZE) {
                engine.processBlock(counter, 0, keyStream, 0);
                incrementCounter();
                keyStreamOffset = 0;
            }
            outBuff[(short) (outOffset + i)] = (byte) (inBuff[(short) (inOffset + i)] ^ keyStream[keyStreamOffset++]);
        }
        return inLength;
    }

    public short doFinal(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) throws CryptoException {
        short produced = update(inBuff, inOffset, inLength, outBuff, outOffset);
        // per the Cipher.doFinal contract, the object stays initialized: reset
        // the counter block and keystream offset so the same IV can stream again
        Util.arrayCopyNonAtomic(initialCounter, (short) 0, counter, (short) 0, BLOCK_SIZE);
        keyStreamOffset = BLOCK_SIZE;
        return produced;
    }

    private void incrementCounter() {
        for (short i = (short) (BLOCK_SIZE - 1); i >= 0; i--) {
            if (++counter[i] != 0) {
                break;
            }
        }
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
}
