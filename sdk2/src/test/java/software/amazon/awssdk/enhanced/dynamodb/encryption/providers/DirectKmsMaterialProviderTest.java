/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except
 * in compliance with the License. A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package software.amazon.awssdk.enhanced.dynamodb.encryption.providers;


import static junit.framework.TestCase.assertEquals;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMappingException;
import com.amazonaws.util.Base64;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.crypto.SecretKey;
import org.hamcrest.core.StringContains;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.enhanced.dynamodb.EncryptionException;
import software.amazon.awssdk.enhanced.dynamodb.encryption.EncryptionContext;
import software.amazon.awssdk.enhanced.dynamodb.encryption.materials.DecryptionMaterials;
import software.amazon.awssdk.enhanced.dynamodb.encryption.materials.EncryptionMaterials;
import software.amazon.awssdk.enhanced.dynamodb.encryption.materials.WrappedRawMaterials;
import software.amazon.awssdk.enhanced.dynamodb.testing.FakeKmsClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;

public class DirectKmsMaterialProviderTest {
  private FakeKmsClient kms;
  private String keyId;
  private Map<String, String> description;
  private EncryptionContext ctx;

  @BeforeEach
  public void setUp() {
    description = new HashMap<>();
    description.put("TestKey", "test value");
    description = Collections.unmodifiableMap(description);
    ctx = new EncryptionContext.Builder().build();
    kms = new FakeKmsClient();
    keyId = kms.createKey().keyMetadata().keyId();
  }

  @Test
  public void simple() throws GeneralSecurityException {
    DirectKmsMaterialProvider prov = new DirectKmsMaterialProvider(kms, keyId);

    EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
    SecretKey encryptionKey = eMat.getEncryptionKey();
    assertNotNull(encryptionKey);
    Key signingKey = eMat.getSigningKey();
    assertNotNull(signingKey);

    DecryptionMaterials dMat = prov.getDecryptionMaterials(ctx(eMat));
    assertEquals(encryptionKey, dMat.getDecryptionKey());
    assertEquals(signingKey, dMat.getVerificationKey());

    String expectedEncAlg =
        encryptionKey.getAlgorithm() + "/" + (encryptionKey.getEncoded().length * 8);
    String expectedSigAlg = signingKey.getAlgorithm() + "/" + (signingKey.getEncoded().length * 8);

    Map<String, String> kmsCtx = kms.getSingleEc();
    assertEquals(expectedEncAlg, kmsCtx.get("*" + WrappedRawMaterials.CONTENT_KEY_ALGORITHM + "*"));
    assertEquals(expectedSigAlg, kmsCtx.get("*amzn-ddb-sig-alg*"));
  }

  @Test
  public void simpleWithKmsEc() throws GeneralSecurityException {
    DirectKmsMaterialProvider prov = new DirectKmsMaterialProvider(kms, keyId);

    Map<String, AttributeValue> attrVals = new HashMap<>();
    attrVals.put("hk", AttributeValue.builder().s("HashKeyValue").build());
    attrVals.put("rk", AttributeValue.builder().s("RangeKeyValue").build());

    ctx =
        new EncryptionContext.Builder()
            .withHashKeyName("hk")
            .withRangeKeyName("rk")
            .withTableName("KmsTableName")
            .withAttributeValues(attrVals)
            .build();
    EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
    SecretKey encryptionKey = eMat.getEncryptionKey();
    assertNotNull(encryptionKey);
    Key signingKey = eMat.getSigningKey();
    assertNotNull(signingKey);
    Map<String, String> kmsCtx = kms.getSingleEc();
    assertEquals("HashKeyValue", kmsCtx.get("hk"));
    assertEquals("RangeKeyValue", kmsCtx.get("rk"));
    assertEquals("KmsTableName", kmsCtx.get("*aws-kms-table*"));

    EncryptionContext dCtx =
        new EncryptionContext.Builder(ctx(eMat))
            .withHashKeyName("hk")
            .withRangeKeyName("rk")
            .withTableName("KmsTableName")
            .withAttributeValues(attrVals)
            .build();

    DecryptionMaterials dMat = prov.getDecryptionMaterials(dCtx);
    assertEquals(encryptionKey, dMat.getDecryptionKey());
    assertEquals(signingKey, dMat.getVerificationKey());
  }

  @Test
  public void simpleWithKmsEc2() throws GeneralSecurityException {
    DirectKmsMaterialProvider prov = new DirectKmsMaterialProvider(kms, keyId);

    Map<String, AttributeValue> attrVals = new HashMap<>();
    attrVals.put("hk", AttributeValue.builder().n("10").build());
    attrVals.put("rk", AttributeValue.builder().n("20").build());

    ctx =
        new EncryptionContext.Builder()
            .withHashKeyName("hk")
            .withRangeKeyName("rk")
            .withTableName("KmsTableName")
            .withAttributeValues(attrVals)
            .build();
    EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
    SecretKey encryptionKey = eMat.getEncryptionKey();
    assertNotNull(encryptionKey);
    Key signingKey = eMat.getSigningKey();
    assertNotNull(signingKey);
    Map<String, String> kmsCtx = kms.getSingleEc();
    assertEquals("10", kmsCtx.get("hk"));
    assertEquals("20", kmsCtx.get("rk"));
    assertEquals("KmsTableName", kmsCtx.get("*aws-kms-table*"));

    EncryptionContext dCtx =
        new EncryptionContext.Builder(ctx(eMat))
            .withHashKeyName("hk")
            .withRangeKeyName("rk")
            .withTableName("KmsTableName")
            .withAttributeValues(attrVals)
            .build();

    DecryptionMaterials dMat = prov.getDecryptionMaterials(dCtx);
    assertEquals(encryptionKey, dMat.getDecryptionKey());
    assertEquals(signingKey, dMat.getVerificationKey());
  }

  @Test
  public void simpleWithKmsEc3() throws GeneralSecurityException {
    DirectKmsMaterialProvider prov = new DirectKmsMaterialProvider(kms, keyId);

    Map<String, AttributeValue> attrVals = new HashMap<>();
    attrVals.put(
        "hk", AttributeValue.builder().b(SdkBytes.fromUtf8String("Foo")).build());
    attrVals.put(
        "rk", AttributeValue.builder().b(SdkBytes.fromUtf8String("Bar")).build());

    ctx =
        new EncryptionContext.Builder()
            .withHashKeyName("hk")
            .withRangeKeyName("rk")
            .withTableName("KmsTableName")
            .withAttributeValues(attrVals)
            .build();
    EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
    SecretKey encryptionKey = eMat.getEncryptionKey();
    assertNotNull(encryptionKey);
    Key signingKey = eMat.getSigningKey();
    assertNotNull(signingKey);
    assertNotNull(signingKey);
    Map<String, String> kmsCtx = kms.getSingleEc();
    assertEquals(Base64.encodeAsString("Foo".getBytes(StandardCharsets.UTF_8)), kmsCtx.get("hk"));
    assertEquals(Base64.encodeAsString("Bar".getBytes(StandardCharsets.UTF_8)), kmsCtx.get("rk"));
    assertEquals("KmsTableName", kmsCtx.get("*aws-kms-table*"));

    EncryptionContext dCtx =
        new EncryptionContext.Builder(ctx(eMat))
            .withHashKeyName("hk")
            .withRangeKeyName("rk")
            .withTableName("KmsTableName")
            .withAttributeValues(attrVals)
            .build();

    DecryptionMaterials dMat = prov.getDecryptionMaterials(dCtx);
    assertEquals(encryptionKey, dMat.getDecryptionKey());
    assertEquals(signingKey, dMat.getVerificationKey());
  }

  @Test
  public void randomEnvelopeKeys() throws GeneralSecurityException {
    DirectKmsMaterialProvider prov = new DirectKmsMaterialProvider(kms, keyId);

    EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
    SecretKey encryptionKey = eMat.getEncryptionKey();
    assertNotNull(encryptionKey);

    EncryptionMaterials eMat2 = prov.getEncryptionMaterials(ctx);
    SecretKey encryptionKey2 = eMat2.getEncryptionKey();

    assertFalse(encryptionKey.equals(encryptionKey2), "Envelope keys must be different");
  }

  @Test
  public void testRefresh() {
    // This does nothing, make sure we don't throw and exception.
    DirectKmsMaterialProvider prov = new DirectKmsMaterialProvider(kms, keyId);
    prov.refresh();
  }

  @Test
  public void explicitContentKeyAlgorithm() throws GeneralSecurityException {
    Map<String, String> desc = new HashMap<>();
    desc.put(WrappedRawMaterials.CONTENT_KEY_ALGORITHM, "AES");

    DirectKmsMaterialProvider prov = new DirectKmsMaterialProvider(kms, keyId, desc);

    EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
    SecretKey encryptionKey = eMat.getEncryptionKey();
    assertNotNull(encryptionKey);

    DecryptionMaterials dMat = prov.getDecryptionMaterials(ctx(eMat));
    assertEquals(
        "AES", eMat.getMaterialDescription().get(WrappedRawMaterials.CONTENT_KEY_ALGORITHM));
    assertEquals(encryptionKey, dMat.getDecryptionKey());
  }

  @Test
  public void explicitContentKeyLength128() throws GeneralSecurityException {
    Map<String, String> desc = new HashMap<>();
    desc.put(WrappedRawMaterials.CONTENT_KEY_ALGORITHM, "AES/128");

    DirectKmsMaterialProvider prov = new DirectKmsMaterialProvider(kms, keyId, desc);

    EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
    SecretKey encryptionKey = eMat.getEncryptionKey();
    assertNotNull(encryptionKey);
    assertEquals(16, encryptionKey.getEncoded().length); // 128 Bits

    DecryptionMaterials dMat = prov.getDecryptionMaterials(ctx(eMat));
    assertEquals(
        "AES/128", eMat.getMaterialDescription().get(WrappedRawMaterials.CONTENT_KEY_ALGORITHM));
    assertEquals("AES", eMat.getEncryptionKey().getAlgorithm());
    assertEquals(encryptionKey, dMat.getDecryptionKey());
  }

  @Test
  public void explicitContentKeyLength256() throws GeneralSecurityException {
    Map<String, String> desc = new HashMap<>();
    desc.put(WrappedRawMaterials.CONTENT_KEY_ALGORITHM, "AES/256");

    DirectKmsMaterialProvider prov = new DirectKmsMaterialProvider(kms, keyId, desc);

    EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
    SecretKey encryptionKey = eMat.getEncryptionKey();
    assertNotNull(encryptionKey);
    assertEquals(32, encryptionKey.getEncoded().length); // 256 Bits

    DecryptionMaterials dMat = prov.getDecryptionMaterials(ctx(eMat));
    assertEquals(
        "AES/256", eMat.getMaterialDescription().get(WrappedRawMaterials.CONTENT_KEY_ALGORITHM));
    assertEquals("AES", eMat.getEncryptionKey().getAlgorithm());
    assertEquals(encryptionKey, dMat.getDecryptionKey());
  }

  @Test
  public void extendedWithDerivedEncryptionKeyId() throws GeneralSecurityException {
    ExtendedKmsMaterialProvider prov =
        new ExtendedKmsMaterialProvider(kms, keyId, "encryptionKeyId");
    String customKeyId = kms.createKey().keyMetadata().keyId();

    Map<String, AttributeValue> attrVals = new HashMap<>();
    attrVals.put("hk", AttributeValue.builder().n("10").build());
    attrVals.put("rk", AttributeValue.builder().n("20").build());
    attrVals.put("encryptionKeyId", AttributeValue.builder().s(customKeyId).build());

    ctx =
        new EncryptionContext.Builder()
            .withHashKeyName("hk")
            .withRangeKeyName("rk")
            .withTableName("KmsTableName")
            .withAttributeValues(attrVals)
            .build();
    EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
    SecretKey encryptionKey = eMat.getEncryptionKey();
    assertNotNull(encryptionKey);
    Key signingKey = eMat.getSigningKey();
    assertNotNull(signingKey);
    Map<String, String> kmsCtx = kms.getSingleEc();
    assertEquals("10", kmsCtx.get("hk"));
    assertEquals("20", kmsCtx.get("rk"));
    assertEquals("KmsTableName", kmsCtx.get("*aws-kms-table*"));

    EncryptionContext dCtx =
        new EncryptionContext.Builder(ctx(eMat))
            .withHashKeyName("hk")
            .withRangeKeyName("rk")
            .withTableName("KmsTableName")
            .withAttributeValues(attrVals)
            .build();

    DecryptionMaterials dMat = prov.getDecryptionMaterials(dCtx);
    assertEquals(encryptionKey, dMat.getDecryptionKey());
    assertEquals(signingKey, dMat.getVerificationKey());
  }

  @Test
  public void encryptionKeyIdMismatch() {
    DirectKmsMaterialProvider directProvider = new DirectKmsMaterialProvider(kms, keyId);
    String customKeyId = kms.createKey().keyMetadata().keyId();

    Map<String, AttributeValue> attrVals = new HashMap<>();
    attrVals.put("hk", AttributeValue.builder().n("10").build());
    attrVals.put("rk", AttributeValue.builder().n("20").build());
    attrVals.put("encryptionKeyId", AttributeValue.builder().s(customKeyId).build());

    ctx =
        new EncryptionContext.Builder()
            .withHashKeyName("hk")
            .withRangeKeyName("rk")
            .withTableName("KmsTableName")
            .withAttributeValues(attrVals)
            .build();
    EncryptionMaterials eMat = directProvider.getEncryptionMaterials(ctx);

    EncryptionContext dCtx =
        new EncryptionContext.Builder(ctx(eMat))
            .withHashKeyName("hk")
            .withRangeKeyName("rk")
            .withTableName("KmsTableName")
            .withAttributeValues(attrVals)
            .build();

    ExtendedKmsMaterialProvider extendedProvider =
        new ExtendedKmsMaterialProvider(kms, keyId, "encryptionKeyId");

    assertThrows(DynamoDBMappingException.class, () ->
    extendedProvider.getDecryptionMaterials(dCtx));
  }

  @Test
  public void encryptionKeyNull() {
    DirectKmsMaterialProvider directProvider = new DirectKmsMaterialProvider(kms, null);
    String customKeyId = kms.createKey().keyMetadata().keyId();

    Map<String, AttributeValue> attrVals = new HashMap<>();
    attrVals.put("hk", AttributeValue.builder().n("10").build());
    attrVals.put("rk", AttributeValue.builder().n("20").build());
    attrVals.put("encryptionKeyId", AttributeValue.builder().s(customKeyId).build());

    ctx =
            new EncryptionContext.Builder()
                    .withHashKeyName("hk")
                    .withRangeKeyName("rk")
                    .withTableName("KmsTableName")
                    .withAttributeValues(attrVals)
                    .build();

    Exception ex = assertThrows(EncryptionException.class, () ->
       directProvider.getEncryptionMaterials(ctx));

    assertThat(ex.getMessage(), new StringContains("Encryption key id is empty."));
  }

  @Test
  public void encryptionKeyEmpty() {
    DirectKmsMaterialProvider directProvider = new DirectKmsMaterialProvider(kms, "");
    String customKeyId = kms.createKey().keyMetadata().keyId();

    Map<String, AttributeValue> attrVals = new HashMap<>();
    attrVals.put("hk", AttributeValue.builder().n("10").build());
    attrVals.put("rk", AttributeValue.builder().n("20").build());
    attrVals.put("encryptionKeyId", AttributeValue.builder().s(customKeyId).build());

    ctx =
            new EncryptionContext.Builder()
                    .withHashKeyName("hk")
                    .withRangeKeyName("rk")
                    .withTableName("KmsTableName")
                    .withAttributeValues(attrVals)
                    .build();

    Exception ex = assertThrows(EncryptionException.class, () ->
            directProvider.getEncryptionMaterials(ctx));

    assertThat(ex.getMessage(), new StringContains("Encryption key id is empty."));
  }

  @Test
  public void missingEncryptionKeyId() throws GeneralSecurityException {
    ExtendedKmsMaterialProvider prov =
        new ExtendedKmsMaterialProvider(kms, keyId, "encryptionKeyId");

    Map<String, AttributeValue> attrVals = new HashMap<>();
    attrVals.put("hk", AttributeValue.builder().n("10").build());
    attrVals.put("rk", AttributeValue.builder().n("20").build());

    ctx =
        new EncryptionContext.Builder()
            .withHashKeyName("hk")
            .withRangeKeyName("rk")
            .withTableName("KmsTableName")
            .withAttributeValues(attrVals)
            .build();

    assertThrows(DynamoDBMappingException.class, () ->
      prov.getEncryptionMaterials(ctx));
  }

  @Test
  public void generateDataKeyIsCalledWith256NumberOfBits() {
    final AtomicBoolean gdkCalled = new AtomicBoolean(false);
    KmsClient kmsSpy =
        new FakeKmsClient() {
          @Override
          public GenerateDataKeyResponse generateDataKey(GenerateDataKeyRequest r) {
            gdkCalled.set(true);
            assertEquals((Integer) 32, r.numberOfBytes());
            assertNull(r.keySpec());
            return super.generateDataKey(r);
          }
        };
    assertFalse(gdkCalled.get());
    new DirectKmsMaterialProvider(kmsSpy, keyId).getEncryptionMaterials(ctx);
    assertTrue(gdkCalled.get());
  }

  private static class ExtendedKmsMaterialProvider extends DirectKmsMaterialProvider {
    private final String encryptionKeyIdAttributeName;

    public ExtendedKmsMaterialProvider(
            KmsClient kms, String encryptionKeyId, String encryptionKeyIdAttributeName) {
      super(kms, encryptionKeyId);

      this.encryptionKeyIdAttributeName = encryptionKeyIdAttributeName;
    }

    @Override
    protected String selectEncryptionKeyId(EncryptionContext context)
        throws DynamoDBMappingException {
      if (!context.getAttributeValues().containsKey(encryptionKeyIdAttributeName)) {
        throw new DynamoDBMappingException("encryption key attribute is not provided");
      }

      return context.getAttributeValues().get(encryptionKeyIdAttributeName).s();
    }

    @Override
    protected void validateEncryptionKeyId(String encryptionKeyId, EncryptionContext context)
        throws DynamoDBMappingException {
      if (!context.getAttributeValues().containsKey(encryptionKeyIdAttributeName)) {
        throw new DynamoDBMappingException("encryption key attribute is not provided");
      }

      String customEncryptionKeyId =
          context.getAttributeValues().get(encryptionKeyIdAttributeName).s();
      if (!customEncryptionKeyId.equals(encryptionKeyId)) {
        throw new DynamoDBMappingException("encryption key ids do not match.");
      }
    }

    @Override
    protected DecryptResponse decrypt(DecryptRequest request, EncryptionContext context) {
      return super.decrypt(request, context);
    }

    @Override
    protected GenerateDataKeyResponse generateDataKey(
            GenerateDataKeyRequest request, EncryptionContext context) {
      return super.generateDataKey(request, context);
    }
  }

  private static EncryptionContext ctx(EncryptionMaterials mat) {
    return new EncryptionContext.Builder()
        .withMaterialDescription(mat.getMaterialDescription())
        .build();
  }
}
