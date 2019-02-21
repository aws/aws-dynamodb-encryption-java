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
package com.amazonaws.services.dynamodbv2.datamodeling.encryption;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 * Identifies keys which should not be used directly with {@link Cipher} but
 * instead contain their own cryptographic logic. This can be used to wrap more
 * complex logic, HSM integration, or service-calls.
 * 
 * <p>
 * Most delegated keys will only support a subset of these operations. (For
 * example, AES keys will generally not support {@link #sign(byte[], String)} or
 * {@link #verify(byte[], byte[], String)} and HMAC keys will generally not
 * support anything except <code>sign</code> and <code>verify</code>.)
 * {@link UnsupportedOperationException} should be thrown in these cases.
 * 
 * @author Greg Rubin 
 */
public interface DelegatedKey extends SecretKey {
    /**
     * Encrypts the provided plaintext and returns a byte-array containing the ciphertext.
     * 
     * @param plainText
     * @param additionalAssociatedData
     *            Optional additional data which must then also be provided for successful
     *            decryption. Both <code>null</code> and arrays of length 0 are treated identically.
     *            Not all keys will support this parameter.
     * @param algorithm
     *            the transformation to be used when encrypting the data
     * @return ciphertext the ciphertext produced by this encryption operation
     * @throws UnsupportedOperationException
     *             if encryption is not supported or if <code>additionalAssociatedData</code> is
     *             provided, but not supported.
     */
    public byte[] encrypt(byte[] plainText, byte[] additionalAssociatedData, String algorithm)
            throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException,
            NoSuchPaddingException;

    /**
     * Decrypts the provided ciphertext and returns a byte-array containing the
     * plaintext.
     * 
     * @param cipherText
     * @param additionalAssociatedData
     *            Optional additional data which was provided during encryption.
     *            Both <code>null</code> and arrays of length 0 are treated
     *            identically. Not all keys will support this parameter.
     * @param algorithm
     *            the transformation to be used when decrypting the data
     * @return plaintext the result of decrypting the input ciphertext
     * @throws UnsupportedOperationException
     *             if decryption is not supported or if
     *             <code>additionalAssociatedData</code> is provided, but not
     *             supported.
     */
    public byte[] decrypt(byte[] cipherText, byte[] additionalAssociatedData, String algorithm)
            throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidAlgorithmParameterException;

    /**
     * Wraps (encrypts) the provided <code>key</code> to make it safe for
     * storage or transmission.
     * 
     * @param key
     * @param additionalAssociatedData
     *            Optional additional data which must then also be provided for
     *            successful unwrapping. Both <code>null</code> and arrays of
     *            length 0 are treated identically. Not all keys will support
     *            this parameter.
     * @param algorithm
     *            the transformation to be used when wrapping the key
     * @return the wrapped key
     * @throws UnsupportedOperationException
     *             if wrapping is not supported or if
     *             <code>additionalAssociatedData</code> is provided, but not
     *             supported.
     */
    public byte[] wrap(Key key, byte[] additionalAssociatedData, String algorithm) throws InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException;

    /**
     * Unwraps (decrypts) the provided <code>wrappedKey</code> to recover the
     * original key.
     * 
     * @param wrappedKey
     * @param additionalAssociatedData
     *            Optional additional data which was provided during wrapping.
     *            Both <code>null</code> and arrays of length 0 are treated
     *            identically. Not all keys will support this parameter.
     * @param algorithm
     *            the transformation to be used when unwrapping the key
     * @return the unwrapped key
     * @throws UnsupportedOperationException
     *             if wrapping is not supported or if
     *             <code>additionalAssociatedData</code> is provided, but not
     *             supported.
     */
    public Key unwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType,
            byte[] additionalAssociatedData, String algorithm) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException;

    /**
     * Calculates and returns a signature for <code>dataToSign</code>.
     * 
     * @param dataToSign
     * @param algorithm
     * @return the signature
     * @throws UnsupportedOperationException if signing is not supported
     */
    public byte[] sign(byte[] dataToSign, String algorithm) throws GeneralSecurityException;

    /**
     * Checks the provided signature for correctness.
     * 
     * @param dataToSign
     * @param signature
     * @param algorithm
     * @return true if and only if the <code>signature</code> matches the <code>dataToSign</code>.
     * @throws UnsupportedOperationException if signature validation is not supported 
     */
    public boolean verify(byte[] dataToSign, byte[] signature, String algorithm);
}
