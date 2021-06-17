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
package com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertFalse;
import static org.testng.AssertJUnit.assertNotNull;

import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionContext;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.DecryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.EncryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.internal.Utils;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class AsymmetricStaticProviderTest {
  private static KeyPair encryptionPair;
  private static SecretKey macKey;
  private static KeyPair sigPair;
  private Map<String, String> description;
  private EncryptionContext ctx;

  @BeforeClass
  public static void setUpClass() throws Exception {
    KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
    rsaGen.initialize(2048, Utils.getRng());
    sigPair = rsaGen.generateKeyPair();
    encryptionPair = rsaGen.generateKeyPair();

    KeyGenerator macGen = KeyGenerator.getInstance("HmacSHA256");
    macGen.init(256, Utils.getRng());
    macKey = macGen.generateKey();
  }

  @BeforeMethod
  public void setUp() {
    description = new HashMap<String, String>();
    description.put("TestKey", "test value");
    description = Collections.unmodifiableMap(description);
    ctx = new EncryptionContext.Builder().build();
  }

  @Test
  public void constructWithMac() throws GeneralSecurityException {
    AsymmetricStaticProvider prov =
        new AsymmetricStaticProvider(
            encryptionPair, macKey, Collections.<String, String>emptyMap());

    EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
    SecretKey encryptionKey = eMat.getEncryptionKey();
    assertNotNull(encryptionKey);
    assertEquals(macKey, eMat.getSigningKey());

    DecryptionMaterials dMat = prov.getDecryptionMaterials(ctx(eMat));
    assertEquals(encryptionKey, dMat.getDecryptionKey());
    assertEquals(macKey, dMat.getVerificationKey());
  }

  @Test
  public void constructWithSigPair() throws GeneralSecurityException {
    AsymmetricStaticProvider prov =
        new AsymmetricStaticProvider(
            encryptionPair, sigPair, Collections.<String, String>emptyMap());

    EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
    SecretKey encryptionKey = eMat.getEncryptionKey();
    assertNotNull(encryptionKey);
    assertEquals(sigPair.getPrivate(), eMat.getSigningKey());

    DecryptionMaterials dMat = prov.getDecryptionMaterials(ctx(eMat));
    assertEquals(encryptionKey, dMat.getDecryptionKey());
    assertEquals(sigPair.getPublic(), dMat.getVerificationKey());
  }

  @Test
  public void randomEnvelopeKeys() throws GeneralSecurityException {
    AsymmetricStaticProvider prov =
        new AsymmetricStaticProvider(
            encryptionPair, macKey, Collections.<String, String>emptyMap());

    EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
    SecretKey encryptionKey = eMat.getEncryptionKey();
    assertNotNull(encryptionKey);
    assertEquals(macKey, eMat.getSigningKey());

    EncryptionMaterials eMat2 = prov.getEncryptionMaterials(ctx);
    SecretKey encryptionKey2 = eMat2.getEncryptionKey();
    assertEquals(macKey, eMat.getSigningKey());

    assertFalse("Envelope keys must be different", encryptionKey.equals(encryptionKey2));
  }

  @Test
  public void testRefresh() {
    // This does nothing, make sure we don't throw and exception.
    AsymmetricStaticProvider prov =
        new AsymmetricStaticProvider(encryptionPair, macKey, description);
    prov.refresh();
  }

  private static EncryptionContext ctx(EncryptionMaterials mat) {
    return new EncryptionContext.Builder()
        .withMaterialDescription(mat.getMaterialDescription())
        .build();
  }
}
