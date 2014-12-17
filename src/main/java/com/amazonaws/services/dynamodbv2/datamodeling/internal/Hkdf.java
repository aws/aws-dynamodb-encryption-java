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
package com.amazonaws.services.dynamodbv2.datamodeling.internal;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import com.amazonaws.util.StringUtils;

/**
 * HMAC-based Key Derivation Function.
 *
 * @see <a href="http://tools.ietf.org/html/rfc5869">RFC 5869</a>
 */
public final class Hkdf {
    private static final byte[] EMPTY_ARRAY = new byte[0];
    private final String algorithm;
    private final Provider provider;

    private SecretKey prk = null;

    /**
     * Returns an <code>Hkdf</code> object using the specified algorithm.
     *
     * @param algorithm
     *            the standard name of the requested MAC algorithm. See the Mac
     *            section in the <a href=
     *            "http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Mac"
     *            > Java Cryptography Architecture Standard Algorithm Name
     *            Documentation</a> for information about standard algorithm
     *            names.
     * @return the new <code>Hkdf</code> object
     * @throws NoSuchAlgorithmException
     *             if no Provider supports a MacSpi implementation for the
     *             specified algorithm.
     */
    public static Hkdf getInstance(final String algorithm)
            throws NoSuchAlgorithmException {
        // Constructed specifically to sanity-test arguments.
        Mac mac = Mac.getInstance(algorithm);
        return new Hkdf(algorithm, mac.getProvider());
    }

    /**
     * Returns an <code>Hkdf</code> object using the specified algorithm.
     *
     * @param algorithm
     *            the standard name of the requested MAC algorithm. See the Mac
     *            section in the <a href=
     *            "http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Mac"
     *            > Java Cryptography Architecture Standard Algorithm Name
     *            Documentation</a> for information about standard algorithm
     *            names.
     * @param provider
     *            the name of the provider
     * @return the new <code>Hkdf</code> object
     * @throws NoSuchAlgorithmException
     *             if a MacSpi implementation for the specified algorithm is not
     *             available from the specified provider.
     * @throws NoSuchProviderException
     *             if the specified provider is not registered in the security
     *             provider list.
     */
    public static Hkdf getInstance(final String algorithm, final String provider)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        // Constructed specifically to sanity-test arguments.
        Mac mac = Mac.getInstance(algorithm, provider);
        return new Hkdf(algorithm, mac.getProvider());
    }

    /**
     * Returns an <code>Hkdf</code> object using the specified algorithm.
     *
     * @param algorithm
     *            the standard name of the requested MAC algorithm. See the Mac
     *            section in the <a href=
     *            "http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Mac"
     *            > Java Cryptography Architecture Standard Algorithm Name
     *            Documentation</a> for information about standard algorithm
     *            names.
     * @param provider
     *            the provider
     * @return the new <code>Hkdf</code> object
     * @throws NoSuchAlgorithmException
     *             if a MacSpi implementation for the specified algorithm is not
     *             available from the specified provider.
     */
    public static Hkdf getInstance(final String algorithm,
            final Provider provider) throws NoSuchAlgorithmException {
        // Constructed specifically to sanity-test arguments.
        Mac mac = Mac.getInstance(algorithm, provider);
        return new Hkdf(algorithm, mac.getProvider());
    }

    /**
     * Initializes this Hkdf with input keying material. A default salt of
     * HashLen zeros will be used (where HashLen is the length of the return
     * value of the supplied algorithm).
     *
     * @param ikm
     *            the Input Keying Material
     */
    public void init(final byte[] ikm) {
        init(ikm, null);
    }

    /**
     * Initializes this Hkdf with input keying material and a salt. If <code>
     * salt</code> is <code>null</code> or of length 0, then a default salt of
     * HashLen zeros will be used (where HashLen is the length of the return
     * value of the supplied algorithm).
     *
     * @param salt
     *            the salt used for key extraction (optional)
     * @param ikm
     *            the Input Keying Material
     */
    public void init(final byte[] ikm, final byte[] salt) {
        byte[] realSalt = (salt == null) ? EMPTY_ARRAY : salt.clone();
        byte[] rawKeyMaterial = EMPTY_ARRAY;
        try {
            Mac extractionMac = Mac.getInstance(algorithm, provider);
            if (realSalt.length == 0) {
                realSalt = new byte[extractionMac.getMacLength()];
                Arrays.fill(realSalt, (byte) 0);
            }
            extractionMac.init(new SecretKeySpec(realSalt, algorithm));
            rawKeyMaterial = extractionMac.doFinal(ikm);
            SecretKeySpec key = new SecretKeySpec(rawKeyMaterial, algorithm);
            Arrays.fill(rawKeyMaterial, (byte) 0);  // Zeroize temporary array
            unsafeInitWithoutKeyExtraction(key);
        } catch (GeneralSecurityException e) {
            // We've already checked all of the parameters so no exceptions
            // should be possible here.
            throw new RuntimeException("Unexpected exception", e);
        } finally {
            Arrays.fill(rawKeyMaterial, (byte) 0);  // Zeroize temporary array
        }
    }

    /**
     * Initializes this Hkdf to use the provided key directly for creation of
     * new keys. If <code>rawKey</code> is not securely generated and uniformly
     * distributed over the total key-space, then this will result in an
     * insecure key derivation function (KDF). <em>DO NOT USE THIS UNLESS YOU
     * ARE ABSOLUTELY POSITIVE THIS IS THE CORRECT THING TO DO.</em>
     *
     * @param rawKey
     *            the pseudorandom key directly used to derive keys
     * @throws InvalidKeyException
     *             if the algorithm for <code>rawKey</code> does not match the
     *             algorithm this Hkdf was created with
     */
    public void unsafeInitWithoutKeyExtraction(final SecretKey rawKey)
            throws InvalidKeyException {
        if (!rawKey.getAlgorithm().equals(algorithm)) {
            throw new InvalidKeyException(
                    "Algorithm for the provided key must match the algorithm for this Hkdf. Expected " +
                    algorithm + " but found " + rawKey.getAlgorithm());
        }

        this.prk = rawKey;
    }

    private Hkdf(final String algorithm, final Provider provider) {
        if (!algorithm.startsWith("Hmac")) {
            throw new IllegalArgumentException("Invalid algorithm " + algorithm
                    + ". Hkdf may only be used with Hmac algorithms.");
        }
        this.algorithm = algorithm;
        this.provider = provider;
    }

    /**
     * Returns a pseudorandom key of <code>length</code> bytes.
     *
     * @param info
     *            optional context and application specific information (can be
     *            a zero-length string). This will be treated as UTF-8.
     * @param length
     *            the length of the output key in bytes
     * @return a pseudorandom key of <code>length</code> bytes.
     * @throws IllegalStateException
     *             if this object has not been initialized
     */
    public byte[] deriveKey(final String info, final int length) throws IllegalStateException {
        return deriveKey((info != null ? info.getBytes(StringUtils.UTF8) : null), length);
    }

    /**
     * Returns a pseudorandom key of <code>length</code> bytes.
     *
     * @param info
     *            optional context and application specific information (can be
     *            a zero-length array).
     * @param length
     *            the length of the output key in bytes
     * @return a pseudorandom key of <code>length</code> bytes.
     * @throws IllegalStateException
     *             if this object has not been initialized
     */
    public byte[] deriveKey(final byte[] info, final int length) throws IllegalStateException {
        byte[] result = new byte[length];
        try {
            deriveKey(info, length, result, 0);
        } catch (ShortBufferException ex) {
            // This exception is impossible as we ensure the buffer is long
            // enough
            throw new RuntimeException(ex);
        }
        return result;
    }

    /**
     * Derives a pseudorandom key of <code>length</code> bytes and stores the
     * result in <code>output</code>.
     *
     * @param info
     *            optional context and application specific information (can be
     *            a zero-length array).
     * @param length
     *            the length of the output key in bytes
     * @param output
     *            the buffer where the pseudorandom key will be stored
     * @param offset
     *            the offset in <code>output</code> where the key will be stored
     * @throws ShortBufferException
     *             if the given output buffer is too small to hold the result
     * @throws IllegalStateException
     *             if this object has not been initialized
     */
    public void deriveKey(final byte[] info, final int length,
            final byte[] output, final int offset) throws ShortBufferException,
            IllegalStateException {
        assertInitialized();
        if (length < 0) {
            throw new IllegalArgumentException("Length must be a non-negative value.");
        }
        if (output.length < offset + length) {
            throw new ShortBufferException();
        }
        Mac mac = createMac();

        if (length > 255 * mac.getMacLength()) {
            throw new IllegalArgumentException(
                    "Requested keys may not be longer than 255 times the underlying HMAC length.");
        }

        byte[] t = EMPTY_ARRAY;
        try {
            int loc = 0;
            byte i = 1;
            while (loc < length) {
                mac.update(t);
                mac.update(info);
                mac.update(i);
                t = mac.doFinal();

                for (int x = 0; x < t.length && loc < length; x++, loc++) {
                    output[loc] = t[x];
                }

                i++;
            }
        } finally {
            Arrays.fill(t, (byte) 0);  // Zeroize temporary array
        }
    }

    private Mac createMac() {
        try {
            Mac mac = Mac.getInstance(algorithm, provider);
            mac.init(prk);
            return mac;
        } catch (NoSuchAlgorithmException ex) {
            // We've already validated that this algorithm is correct.
            throw new RuntimeException(ex);
        } catch (InvalidKeyException ex) {
            // We've already validated that this key is correct.
            throw new RuntimeException(ex);
        }
    }

    /**
     * Throws an <code>IllegalStateException</code> if this object has not been
     * initialized.
     *
     * @throws IllegalStateException
     *             if this object has not been initialized
     */
    private void assertInitialized() throws IllegalStateException {
        if (prk == null) {
            throw new IllegalStateException("Hkdf has not been initialized");
        }
    }
}
