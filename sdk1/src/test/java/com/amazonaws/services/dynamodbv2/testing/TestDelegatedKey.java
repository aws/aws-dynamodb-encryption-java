/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
package com.amazonaws.services.dynamodbv2.testing;

import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DelegatedKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class TestDelegatedKey implements DelegatedKey {
    private static final long serialVersionUID = 1L;

    private final Key realKey;

    public TestDelegatedKey(Key key) {
        this.realKey = key;
    }

    @Override
    public String getAlgorithm() {
        return "DELEGATED:" + realKey.getAlgorithm();
    }

    @Override
    public byte[] getEncoded() {
        return realKey.getEncoded();
    }

    @Override
    public String getFormat() {
        return realKey.getFormat();
    }

    @Override
    public byte[] encrypt(byte[] plainText, byte[] additionalAssociatedData, String algorithm)
            throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException,
            NoSuchPaddingException {
        Cipher cipher = Cipher.getInstance(extractAlgorithm(algorithm));
        cipher.init(Cipher.ENCRYPT_MODE, realKey);
        byte[] iv = cipher.getIV();
        byte[] result = new byte[cipher.getOutputSize(plainText.length) + iv.length + 1];
        result[0] = (byte) iv.length;
        System.arraycopy(iv, 0, result, 1, iv.length);
        try {
            cipher.doFinal(plainText, 0, plainText.length, result, iv.length + 1);
        } catch (ShortBufferException e) {
            throw new RuntimeException(e);
        }
        return result;
    }

    @Override
    public byte[] decrypt(byte[] cipherText, byte[] additionalAssociatedData, String algorithm)
            throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidAlgorithmParameterException {
        final byte ivLength = cipherText[0];
        IvParameterSpec iv = new IvParameterSpec(cipherText, 1, ivLength);
        Cipher cipher = Cipher.getInstance(extractAlgorithm(algorithm));
        cipher.init(Cipher.DECRYPT_MODE, realKey, iv);
        return cipher.doFinal(cipherText, ivLength + 1, cipherText.length - ivLength - 1);
    }

    @Override
    public byte[] wrap(Key key, byte[] additionalAssociatedData, String algorithm) throws InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(extractAlgorithm(algorithm));
        cipher.init(Cipher.WRAP_MODE, realKey);
        return cipher.wrap(key);
    }

    @Override
    public Key unwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType,
                      byte[] additionalAssociatedData, String algorithm) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException {
        Cipher cipher = Cipher.getInstance(extractAlgorithm(algorithm));
        cipher.init(Cipher.UNWRAP_MODE, realKey);
        return cipher.unwrap(wrappedKey, wrappedKeyAlgorithm, wrappedKeyType);
    }

    @Override
    public byte[] sign(byte[] dataToSign, String algorithm) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(extractAlgorithm(algorithm));
        mac.init(realKey);
        return mac.doFinal(dataToSign);
    }

    @Override
    public boolean verify(byte[] dataToSign, byte[] signature, String algorithm) {
        try {
            byte[] expected = sign(dataToSign, extractAlgorithm(algorithm));
            return MessageDigest.isEqual(expected, signature);
        } catch (GeneralSecurityException ex) {
            return false;
        }
    }

    private String extractAlgorithm(String alg) {
        if (alg.startsWith(getAlgorithm())) {
            return alg.substring(10);
        } else {
            return alg;
        }
    }
}
