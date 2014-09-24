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

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.crypto.KeyGenerator;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.amazonaws.services.dynamodbv2.model.AttributeValue;

public class DynamoDBSignerTest {
    // These use the Key type (rather than PublicKey, PrivateKey, and SecretKey)
    // to test the routing logic within the signer.
    private static Key pubKey;
    private static Key privKey;
    private static Key macKey;
    private static SecureRandom rnd;
    private DynamoDBSigner signer;
    
    @BeforeClass
    public static void setUpClass() throws Exception {
        rnd = new SecureRandom();
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048, rnd);
        KeyPair sigPair = rsaGen.generateKeyPair();
        pubKey = sigPair.getPublic();
        privKey = sigPair.getPrivate();
        
        KeyGenerator macGen = KeyGenerator.getInstance("HmacSHA256");
        macGen.init(256, rnd);
        macKey = macGen.generateKey();
        
        
    }
    
    @Before
    public void setUp() {
        signer = DynamoDBSigner.getInstance("SHA256withRSA", rnd);
    }

    @Test(expected=UnsupportedOperationException.class)
    public void testBadAlgorithm() {
        DynamoDBSigner.getInstance("badAlgorithm", rnd);
    }

    @Test
    public void mac() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();
        
        itemAttributes.put("Key1", new AttributeValue().withS("Value1"));
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", new AttributeValue().withN("100"));
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key3", new AttributeValue().withB(ByteBuffer.wrap(new byte[] { 0, 1, 2, 3})));
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN, EncryptionFlags.ENCRYPT));
        byte[] signature = signer.calculateSignature(itemAttributes, attributeFlags, new byte[0], macKey);
        
        signer.verifySignature(itemAttributes, attributeFlags, new byte[0], macKey, ByteBuffer.wrap(signature));
    }

    @Test
    public void macLists() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();
        
        itemAttributes.put("Key1", new AttributeValue().withSS("Value1", "Value2", "Value3"));
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", new AttributeValue().withNS("100", "200", "300"));
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key3", new AttributeValue().withBS(ByteBuffer.wrap(new byte[] { 0, 1, 2, 3}),
                                                               ByteBuffer.wrap(new byte[] { 3, 2, 1})));
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN, EncryptionFlags.ENCRYPT));
        byte[] signature = signer.calculateSignature(itemAttributes, attributeFlags, new byte[0], macKey);
        
        signer.verifySignature(itemAttributes, attributeFlags, new byte[0], macKey, ByteBuffer.wrap(signature));
    }
    
    @Test
    public void macListsUnsorted() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();
        
        itemAttributes.put("Key1", new AttributeValue().withSS("Value3", "Value1", "Value2"));
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", new AttributeValue().withNS("100", "300", "200"));
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key3", new AttributeValue().withBS(ByteBuffer.wrap(new byte[] { 3, 2, 1}),
                                                               ByteBuffer.wrap(new byte[] { 0, 1, 2, 3})));
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN, EncryptionFlags.ENCRYPT));
        byte[] signature = signer.calculateSignature(itemAttributes, attributeFlags, new byte[0], macKey);
        
        Map<String, AttributeValue> scrambledAttributes = new HashMap<String, AttributeValue>();
        scrambledAttributes.put("Key1", new AttributeValue().withSS("Value1", "Value2", "Value3"));
        scrambledAttributes.put("Key2", new AttributeValue().withNS("100", "200", "300"));
        scrambledAttributes.put("Key3", new AttributeValue().withBS(ByteBuffer.wrap(new byte[] { 0, 1, 2, 3}),
                                                               ByteBuffer.wrap(new byte[] { 3, 2, 1})));

        signer.verifySignature(scrambledAttributes, attributeFlags, new byte[0], macKey, ByteBuffer.wrap(signature));
    }
    
    @Test
    public void macNoAdMatchesEmptyAd() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();
        
        itemAttributes.put("Key1", new AttributeValue().withS("Value1"));
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", new AttributeValue().withN("100"));
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key3", new AttributeValue().withB(ByteBuffer.wrap(new byte[] { 0, 1, 2, 3})));
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN, EncryptionFlags.ENCRYPT));
        byte[] signature = signer.calculateSignature(itemAttributes, attributeFlags, null, macKey);
        
        signer.verifySignature(itemAttributes, attributeFlags, new byte[0], macKey, ByteBuffer.wrap(signature));
    }
    
    @Test
    public void macWithIgnoredChange() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();
        
        itemAttributes.put("Key1", new AttributeValue().withS("Value1"));
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", new AttributeValue().withN("100"));
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key3", new AttributeValue().withB(ByteBuffer.wrap(new byte[] { 0, 1, 2, 3})));
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN, EncryptionFlags.ENCRYPT));
        itemAttributes.put("Key4", new AttributeValue().withS("Ignored Value"));
        byte[] signature = signer.calculateSignature(itemAttributes, attributeFlags, new byte[0], macKey);
        
        
        itemAttributes.put("Key4", new AttributeValue().withS("New Ignored Value"));
        signer.verifySignature(itemAttributes, attributeFlags, new byte[0], macKey, ByteBuffer.wrap(signature));
    }
    
    @Test(expected=SignatureException.class)
    public void macChangedValue() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();
        
        itemAttributes.put("Key1", new AttributeValue().withS("Value1"));
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", new AttributeValue().withN("100"));
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key3", new AttributeValue().withB(ByteBuffer.wrap(new byte[] { 0, 1, 2, 3})));
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN, EncryptionFlags.ENCRYPT));
        byte[] signature = signer.calculateSignature(itemAttributes, attributeFlags, new byte[0], macKey);
        
        itemAttributes.get("Key2").setN("99");
        signer.verifySignature(itemAttributes, attributeFlags, new byte[0], macKey, ByteBuffer.wrap(signature));
    }
    
    @Test(expected=SignatureException.class)
    public void macChangedFlag() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();
        
        itemAttributes.put("Key1", new AttributeValue().withS("Value1"));
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", new AttributeValue().withN("100"));
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key3", new AttributeValue().withB(ByteBuffer.wrap(new byte[] { 0, 1, 2, 3})));
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN, EncryptionFlags.ENCRYPT));
        byte[] signature = signer.calculateSignature(itemAttributes, attributeFlags, new byte[0], macKey);
        
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN));
        signer.verifySignature(itemAttributes, attributeFlags, new byte[0], macKey, ByteBuffer.wrap(signature));
    }
    
    @Test(expected=SignatureException.class)
    public void macChangedAssociatedData() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();
        
        itemAttributes.put("Key1", new AttributeValue().withS("Value1"));
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", new AttributeValue().withN("100"));
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key3", new AttributeValue().withB(ByteBuffer.wrap(new byte[] { 0, 1, 2, 3})));
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN, EncryptionFlags.ENCRYPT));
        byte[] signature = signer.calculateSignature(itemAttributes, attributeFlags, new byte[] {3, 2, 1}, macKey);
        
        signer.verifySignature(itemAttributes, attributeFlags, new byte[] {1, 2, 3}, macKey, ByteBuffer.wrap(signature));
    }
    
    @Test
    public void sig() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();
        
        itemAttributes.put("Key1", new AttributeValue().withS("Value1"));
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", new AttributeValue().withN("100"));
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key3", new AttributeValue().withB(ByteBuffer.wrap(new byte[] { 0, 1, 2, 3})));
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN, EncryptionFlags.ENCRYPT));
        byte[] signature = signer.calculateSignature(itemAttributes, attributeFlags, new byte[0], privKey);
        
        signer.verifySignature(itemAttributes, attributeFlags, new byte[0], pubKey, ByteBuffer.wrap(signature));
    }
    
    @Test
    public void sigWithReadOnlySignature() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();
        
        itemAttributes.put("Key1", new AttributeValue().withS("Value1"));
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", new AttributeValue().withN("100"));
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key3", new AttributeValue().withB(ByteBuffer.wrap(new byte[] { 0, 1, 2, 3})));
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN, EncryptionFlags.ENCRYPT));
        byte[] signature = signer.calculateSignature(itemAttributes, attributeFlags, new byte[0], privKey);
        
        signer.verifySignature(itemAttributes, attributeFlags, new byte[0], pubKey, ByteBuffer.wrap(signature).asReadOnlyBuffer());
    }
    
    @Test
    public void sigNoAdMatchesEmptyAd() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();
        
        itemAttributes.put("Key1", new AttributeValue().withS("Value1"));
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", new AttributeValue().withN("100"));
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key3", new AttributeValue().withB(ByteBuffer.wrap(new byte[] { 0, 1, 2, 3})));
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN, EncryptionFlags.ENCRYPT));
        byte[] signature = signer.calculateSignature(itemAttributes, attributeFlags, null, privKey);
        
        signer.verifySignature(itemAttributes, attributeFlags, new byte[0], pubKey, ByteBuffer.wrap(signature));
    }
    
    @Test
    public void sigWithIgnoredChange() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();
        
        itemAttributes.put("Key1", new AttributeValue().withS("Value1"));
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", new AttributeValue().withN("100"));
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key3", new AttributeValue().withB(ByteBuffer.wrap(new byte[] { 0, 1, 2, 3})));
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN, EncryptionFlags.ENCRYPT));
        itemAttributes.put("Key4", new AttributeValue().withS("Ignored Value"));
        byte[] signature = signer.calculateSignature(itemAttributes, attributeFlags, new byte[0], privKey);
        
        itemAttributes.put("Key4", new AttributeValue().withS("New Ignored Value"));
        signer.verifySignature(itemAttributes, attributeFlags, new byte[0], pubKey, ByteBuffer.wrap(signature));
    }
    
    @Test(expected=SignatureException.class)
    public void sigChangedValue() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();
        
        itemAttributes.put("Key1", new AttributeValue().withS("Value1"));
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", new AttributeValue().withN("100"));
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key3", new AttributeValue().withB(ByteBuffer.wrap(new byte[] { 0, 1, 2, 3})));
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN, EncryptionFlags.ENCRYPT));
        byte[] signature = signer.calculateSignature(itemAttributes, attributeFlags, new byte[0], privKey);
        
        itemAttributes.get("Key2").setN("99");
        signer.verifySignature(itemAttributes, attributeFlags, new byte[0], pubKey, ByteBuffer.wrap(signature));
    }
    
    @Test(expected=SignatureException.class)
    public void sigChangedFlag() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();
        
        itemAttributes.put("Key1", new AttributeValue().withS("Value1"));
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", new AttributeValue().withN("100"));
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key3", new AttributeValue().withB(ByteBuffer.wrap(new byte[] { 0, 1, 2, 3})));
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN, EncryptionFlags.ENCRYPT));
        byte[] signature = signer.calculateSignature(itemAttributes, attributeFlags, new byte[0], privKey);
        
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN));
        signer.verifySignature(itemAttributes, attributeFlags, new byte[0], pubKey, ByteBuffer.wrap(signature));
    }
    
    @Test(expected=SignatureException.class)
    public void sigChangedAssociatedData() throws GeneralSecurityException {
        Map<String, AttributeValue> itemAttributes = new HashMap<String, AttributeValue>();
        Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();
        
        itemAttributes.put("Key1", new AttributeValue().withS("Value1"));
        attributeFlags.put("Key1", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key2", new AttributeValue().withN("100"));
        attributeFlags.put("Key2", EnumSet.of(EncryptionFlags.SIGN));
        itemAttributes.put("Key3", new AttributeValue().withB(ByteBuffer.wrap(new byte[] { 0, 1, 2, 3})));
        attributeFlags.put("Key3", EnumSet.of(EncryptionFlags.SIGN, EncryptionFlags.ENCRYPT));
        byte[] signature = signer.calculateSignature(itemAttributes, attributeFlags, new byte[0], privKey);
        
        signer.verifySignature(itemAttributes, attributeFlags, new byte[] {1, 2, 3}, pubKey, ByteBuffer.wrap(signature));
    }
}
