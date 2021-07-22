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

import com.amazonaws.services.dynamodbv2.datamodeling.AttributeEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.DecryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.EncryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers.EncryptionMaterialsProvider;
import com.amazonaws.services.dynamodbv2.datamodeling.internal.AttributeValueMarshaller;
import com.amazonaws.services.dynamodbv2.datamodeling.internal.ByteBufferInputStream;
import com.amazonaws.services.dynamodbv2.datamodeling.internal.Utils;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * The low-level API used by {@link AttributeEncryptor} to perform crypto operations on the record
 * attributes.
 *
 * <p>For guidance on performing a safe data model change procedure, please see <a
 * href="https://docs.aws.amazon.com/dynamodb-encryption-client/latest/devguide/data-model.html"
 * target="_blank"> DynamoDB Encryption Client Developer Guide: Changing your data model</a>
 *
 * @author Greg Rubin
 */
public class DynamoDBEncryptor {
  private static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA256withRSA";
  private static final String DEFAULT_METADATA_FIELD = "*amzn-ddb-map-desc*";
  private static final String DEFAULT_SIGNATURE_FIELD = "*amzn-ddb-map-sig*";
  private static final String DEFAULT_DESCRIPTION_BASE = "amzn-ddb-map-"; // Same as the Mapper
  private static final Charset UTF8 = Charset.forName("UTF-8");
  private static final String SYMMETRIC_ENCRYPTION_MODE = "/CBC/PKCS5Padding";
  private static final ConcurrentHashMap<String, Integer> BLOCK_SIZE_CACHE =
      new ConcurrentHashMap<>();
  private static final Function<String, Integer> BLOCK_SIZE_CALCULATOR =
      (transformation) -> {
        try {
          final Cipher c = Cipher.getInstance(transformation);
          return c.getBlockSize();
        } catch (final GeneralSecurityException ex) {
          throw new IllegalArgumentException("Algorithm does not exist", ex);
        }
      };

  private static final int CURRENT_VERSION = 0;

  private String signatureFieldName = DEFAULT_SIGNATURE_FIELD;
  private String materialDescriptionFieldName = DEFAULT_METADATA_FIELD;

  private EncryptionMaterialsProvider encryptionMaterialsProvider;
  private final String descriptionBase;
  private final String symmetricEncryptionModeHeader;
  private final String signingAlgorithmHeader;

  public static final String DEFAULT_SIGNING_ALGORITHM_HEADER =
      DEFAULT_DESCRIPTION_BASE + "signingAlg";
  private Function<EncryptionContext, EncryptionContext> encryptionContextOverrideOperator;

  protected DynamoDBEncryptor(EncryptionMaterialsProvider provider, String descriptionBase) {
    this.encryptionMaterialsProvider = provider;
    this.descriptionBase = descriptionBase;
    symmetricEncryptionModeHeader = this.descriptionBase + "sym-mode";
    signingAlgorithmHeader = this.descriptionBase + "signingAlg";
  }

  public static DynamoDBEncryptor getInstance(
      EncryptionMaterialsProvider provider, String descriptionbase) {
    return new DynamoDBEncryptor(provider, descriptionbase);
  }

  public static DynamoDBEncryptor getInstance(EncryptionMaterialsProvider provider) {
    return getInstance(provider, DEFAULT_DESCRIPTION_BASE);
  }

  /**
   * Returns a decrypted version of the provided DynamoDb record. The signature is verified across
   * all provided fields. All fields (except those listed in <code>doNotEncrypt</code> are
   * decrypted.
   *
   * @param itemAttributes the DynamoDbRecord
   * @param context additional information used to successfully select the encryption materials and
   *     decrypt the data. This should include (at least) the tableName and the materialDescription.
   * @param doNotDecrypt those fields which should not be encrypted
   * @return a plaintext version of the DynamoDb record
   * @throws SignatureException if the signature is invalid or cannot be verified
   * @throws GeneralSecurityException
   */
  public Map<String, AttributeValue> decryptAllFieldsExcept(
      Map<String, AttributeValue> itemAttributes, EncryptionContext context, String... doNotDecrypt)
      throws GeneralSecurityException {
    return decryptAllFieldsExcept(itemAttributes, context, Arrays.asList(doNotDecrypt));
  }

  /** @see #decryptAllFieldsExcept(Map, EncryptionContext, String...) */
  public Map<String, AttributeValue> decryptAllFieldsExcept(
      Map<String, AttributeValue> itemAttributes,
      EncryptionContext context,
      Collection<String> doNotDecrypt)
      throws GeneralSecurityException {
    Map<String, Set<EncryptionFlags>> attributeFlags =
        allDecryptionFlagsExcept(itemAttributes, doNotDecrypt);
    return decryptRecord(itemAttributes, attributeFlags, context);
  }

  /**
   * Returns the decryption flags for all item attributes except for those explicitly specified to
   * be excluded.
   *
   * @param doNotDecrypt fields to be excluded
   */
  public Map<String, Set<EncryptionFlags>> allDecryptionFlagsExcept(
      Map<String, AttributeValue> itemAttributes, String... doNotDecrypt) {
    return allDecryptionFlagsExcept(itemAttributes, Arrays.asList(doNotDecrypt));
  }

  /**
   * Returns the decryption flags for all item attributes except for those explicitly specified to
   * be excluded.
   *
   * @param doNotDecrypt fields to be excluded
   */
  public Map<String, Set<EncryptionFlags>> allDecryptionFlagsExcept(
      Map<String, AttributeValue> itemAttributes, Collection<String> doNotDecrypt) {
    Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();

    for (String fieldName : doNotDecrypt) {
      attributeFlags.put(fieldName, EnumSet.of(EncryptionFlags.SIGN));
    }

    for (String fieldName : itemAttributes.keySet()) {
      if (!attributeFlags.containsKey(fieldName)
          && !fieldName.equals(getMaterialDescriptionFieldName())
          && !fieldName.equals(getSignatureFieldName())) {
        attributeFlags.put(fieldName, EnumSet.of(EncryptionFlags.ENCRYPT, EncryptionFlags.SIGN));
      }
    }
    return attributeFlags;
  }

  /**
   * Returns an encrypted version of the provided DynamoDb record. All fields are signed. All fields
   * (except those listed in <code>doNotEncrypt</code>) are encrypted.
   *
   * @param itemAttributes a DynamoDb Record
   * @param context additional information used to successfully select the encryption materials and
   *     encrypt the data. This should include (at least) the tableName.
   * @param doNotEncrypt those fields which should not be encrypted
   * @return a ciphertext version of the DynamoDb record
   * @throws GeneralSecurityException
   */
  public Map<String, AttributeValue> encryptAllFieldsExcept(
      Map<String, AttributeValue> itemAttributes, EncryptionContext context, String... doNotEncrypt)
      throws GeneralSecurityException {

    return encryptAllFieldsExcept(itemAttributes, context, Arrays.asList(doNotEncrypt));
  }

  public Map<String, AttributeValue> encryptAllFieldsExcept(
      Map<String, AttributeValue> itemAttributes,
      EncryptionContext context,
      Collection<String> doNotEncrypt)
      throws GeneralSecurityException {
    Map<String, Set<EncryptionFlags>> attributeFlags =
        allEncryptionFlagsExcept(itemAttributes, doNotEncrypt);
    return encryptRecord(itemAttributes, attributeFlags, context);
  }

  /**
   * Returns the encryption flags for all item attributes except for those explicitly specified to
   * be excluded.
   *
   * @param doNotEncrypt fields to be excluded
   */
  public Map<String, Set<EncryptionFlags>> allEncryptionFlagsExcept(
      Map<String, AttributeValue> itemAttributes, String... doNotEncrypt) {
    return allEncryptionFlagsExcept(itemAttributes, Arrays.asList(doNotEncrypt));
  }

  /**
   * Returns the encryption flags for all item attributes except for those explicitly specified to
   * be excluded.
   *
   * @param doNotEncrypt fields to be excluded
   */
  public Map<String, Set<EncryptionFlags>> allEncryptionFlagsExcept(
      Map<String, AttributeValue> itemAttributes, Collection<String> doNotEncrypt) {
    Map<String, Set<EncryptionFlags>> attributeFlags = new HashMap<String, Set<EncryptionFlags>>();
    for (String fieldName : doNotEncrypt) {
      attributeFlags.put(fieldName, EnumSet.of(EncryptionFlags.SIGN));
    }

    for (String fieldName : itemAttributes.keySet()) {
      if (!attributeFlags.containsKey(fieldName)) {
        attributeFlags.put(fieldName, EnumSet.of(EncryptionFlags.ENCRYPT, EncryptionFlags.SIGN));
      }
    }
    return attributeFlags;
  }

  public Map<String, AttributeValue> decryptRecord(
      Map<String, AttributeValue> itemAttributes,
      Map<String, Set<EncryptionFlags>> attributeFlags,
      EncryptionContext context)
      throws GeneralSecurityException {
    if (attributeFlags.isEmpty()) {
      return itemAttributes;
    }

    if (!itemAttributes.containsKey(signatureFieldName)
        && !itemAttributes.containsKey(materialDescriptionFieldName)) {
      // Check if any key from the received raw document is marked with EncryptionFlags in model
      if (isAnyKeyMarkedWithEncryptionFlags(itemAttributes.keySet(), attributeFlags)) {
        throw new IllegalArgumentException("Bad data, missing " + signatureFieldName);
      } else {
        return itemAttributes;
      }
    }
    // Copy to avoid changing anyone elses objects
    itemAttributes = new HashMap<String, AttributeValue>(itemAttributes);

    Map<String, String> materialDescription = Collections.emptyMap();
    DecryptionMaterials materials;
    SecretKey decryptionKey;

    DynamoDBSigner signer = DynamoDBSigner.getInstance(DEFAULT_SIGNATURE_ALGORITHM, Utils.getRng());

    if (itemAttributes.containsKey(materialDescriptionFieldName)) {
      materialDescription = unmarshallDescription(itemAttributes.get(materialDescriptionFieldName));
    }
    // Copy the material description and attribute values into the context
    context =
        new EncryptionContext.Builder(context)
            .withMaterialDescription(materialDescription)
            .withAttributeValues(itemAttributes)
            .build();

    Function<EncryptionContext, EncryptionContext> encryptionContextOverrideOperator =
        getEncryptionContextOverrideOperator();
    if (encryptionContextOverrideOperator != null) {
      context = encryptionContextOverrideOperator.apply(context);
    }

    materials = encryptionMaterialsProvider.getDecryptionMaterials(context);
    decryptionKey = materials.getDecryptionKey();
    if (materialDescription.containsKey(signingAlgorithmHeader)) {
      String signingAlg = materialDescription.get(signingAlgorithmHeader);
      signer = DynamoDBSigner.getInstance(signingAlg, Utils.getRng());
    }

    ByteBuffer signature;
    if (!itemAttributes.containsKey(signatureFieldName)
        || itemAttributes.get(signatureFieldName).getB() == null) {
      signature = ByteBuffer.allocate(0);
    } else {
      signature = itemAttributes.get(signatureFieldName).getB().asReadOnlyBuffer();
    }
    itemAttributes.remove(signatureFieldName);

    String associatedData = "TABLE>" + context.getTableName() + "<TABLE";
    signer.verifySignature(
        itemAttributes,
        attributeFlags,
        associatedData.getBytes(UTF8),
        materials.getVerificationKey(),
        signature);
    itemAttributes.remove(materialDescriptionFieldName);

    actualDecryption(itemAttributes, attributeFlags, decryptionKey, materialDescription);
    return itemAttributes;
  }

  private boolean isAnyKeyMarkedWithEncryptionFlags(Set<String> keysToCheck,
                                                    Map<String, Set<EncryptionFlags>> attributeFlags) {
    return keysToCheck.stream()
            .anyMatch(key -> !attributeFlags.get(key).isEmpty());
  }

  /**
   * Returns the encrypted (and signed) record, which is a map of item attributes. There is no side
   * effect on the input parameters upon calling this method.
   *
   * @param itemAttributes the input record
   * @param attributeFlags the corresponding encryption flags
   * @param context encryption context
   * @return a new instance of item attributes encrypted as necessary
   * @throws GeneralSecurityException if failed to encrypt the record
   */
  public Map<String, AttributeValue> encryptRecord(
      Map<String, AttributeValue> itemAttributes,
      Map<String, Set<EncryptionFlags>> attributeFlags,
      EncryptionContext context)
      throws GeneralSecurityException {
    if (attributeFlags.isEmpty()) {
      return itemAttributes;
    }
    // Copy to avoid changing anyone elses objects
    itemAttributes = new HashMap<String, AttributeValue>(itemAttributes);

    // Copy the attribute values into the context
    context = new EncryptionContext.Builder(context).withAttributeValues(itemAttributes).build();

    Function<EncryptionContext, EncryptionContext> encryptionContextOverrideOperator =
        getEncryptionContextOverrideOperator();
    if (encryptionContextOverrideOperator != null) {
      context = encryptionContextOverrideOperator.apply(context);
    }

    EncryptionMaterials materials = encryptionMaterialsProvider.getEncryptionMaterials(context);
    // We need to copy this because we modify it to record other encryption details
    Map<String, String> materialDescription =
        new HashMap<String, String>(materials.getMaterialDescription());
    SecretKey encryptionKey = materials.getEncryptionKey();

    actualEncryption(itemAttributes, attributeFlags, materialDescription, encryptionKey);

    // The description must be stored after encryption because its data
    // is necessary for proper decryption.
    final String signingAlgo = materialDescription.get(signingAlgorithmHeader);
    DynamoDBSigner signer;
    if (signingAlgo != null) {
      signer = DynamoDBSigner.getInstance(signingAlgo, Utils.getRng());
    } else {
      signer = DynamoDBSigner.getInstance(DEFAULT_SIGNATURE_ALGORITHM, Utils.getRng());
    }

    if (materials.getSigningKey() instanceof PrivateKey) {
      materialDescription.put(signingAlgorithmHeader, signer.getSigningAlgorithm());
    }
    if (!materialDescription.isEmpty()) {
      itemAttributes.put(materialDescriptionFieldName, marshallDescription(materialDescription));
    }

    String associatedData = "TABLE>" + context.getTableName() + "<TABLE";
    byte[] signature =
        signer.calculateSignature(
            itemAttributes,
            attributeFlags,
            associatedData.getBytes(UTF8),
            materials.getSigningKey());

    AttributeValue signatureAttribute = new AttributeValue();
    signatureAttribute.setB(ByteBuffer.wrap(signature));
    itemAttributes.put(signatureFieldName, signatureAttribute);

    return itemAttributes;
  }

  private void actualDecryption(
      Map<String, AttributeValue> itemAttributes,
      Map<String, Set<EncryptionFlags>> attributeFlags,
      SecretKey encryptionKey,
      Map<String, String> materialDescription)
      throws GeneralSecurityException {
    final String encryptionMode =
        encryptionKey != null
            ? encryptionKey.getAlgorithm() + materialDescription.get(symmetricEncryptionModeHeader)
            : null;
    Cipher cipher = null;
    int blockSize = -1;

    for (Map.Entry<String, AttributeValue> entry : itemAttributes.entrySet()) {
      Set<EncryptionFlags> flags = attributeFlags.get(entry.getKey());
      if (flags != null && flags.contains(EncryptionFlags.ENCRYPT)) {
        if (!flags.contains(EncryptionFlags.SIGN)) {
          throw new IllegalArgumentException(
              "All encrypted fields must be signed. Bad field: " + entry.getKey());
        }
        ByteBuffer plainText;
        ByteBuffer cipherText = entry.getValue().getB().asReadOnlyBuffer();
        cipherText.rewind();
        if (encryptionKey instanceof DelegatedKey) {
          plainText =
              ByteBuffer.wrap(
                  ((DelegatedKey) encryptionKey)
                      .decrypt(toByteArray(cipherText), null, encryptionMode));
        } else {
          if (cipher == null) {
            blockSize = getBlockSize(encryptionMode);
            cipher = Cipher.getInstance(encryptionMode);
          }
          byte[] iv = new byte[blockSize];
          cipherText.get(iv);
          cipher.init(Cipher.DECRYPT_MODE, encryptionKey, new IvParameterSpec(iv), Utils.getRng());
          plainText = ByteBuffer.allocate(cipher.getOutputSize(cipherText.remaining()));
          cipher.doFinal(cipherText, plainText);
          plainText.rewind();
        }
        entry.setValue(AttributeValueMarshaller.unmarshall(plainText));
      }
    }
  }

  protected static int getBlockSize(final String encryptionMode) {
    return BLOCK_SIZE_CACHE.computeIfAbsent(encryptionMode, BLOCK_SIZE_CALCULATOR);
  }

  /**
   * This method has the side effect of replacing the plaintext attribute-values of "itemAttributes"
   * with ciphertext attribute-values (which are always in the form of ByteBuffer) as per the
   * corresponding attribute flags.
   */
  private void actualEncryption(
      Map<String, AttributeValue> itemAttributes,
      Map<String, Set<EncryptionFlags>> attributeFlags,
      Map<String, String> materialDescription,
      SecretKey encryptionKey)
      throws GeneralSecurityException {
    String encryptionMode = null;
    if (encryptionKey != null) {
      materialDescription.put(this.symmetricEncryptionModeHeader, SYMMETRIC_ENCRYPTION_MODE);
      encryptionMode = encryptionKey.getAlgorithm() + SYMMETRIC_ENCRYPTION_MODE;
    }
    Cipher cipher = null;
    int blockSize = -1;

    for (Map.Entry<String, AttributeValue> entry : itemAttributes.entrySet()) {
      Set<EncryptionFlags> flags = attributeFlags.get(entry.getKey());
      if (flags != null && flags.contains(EncryptionFlags.ENCRYPT)) {
        if (!flags.contains(EncryptionFlags.SIGN)) {
          throw new IllegalArgumentException(
              "All encrypted fields must be signed. Bad field: " + entry.getKey());
        }
        ByteBuffer plainText = AttributeValueMarshaller.marshall(entry.getValue());
        plainText.rewind();
        ByteBuffer cipherText;
        if (encryptionKey instanceof DelegatedKey) {
          DelegatedKey dk = (DelegatedKey) encryptionKey;
          cipherText = ByteBuffer.wrap(dk.encrypt(toByteArray(plainText), null, encryptionMode));
        } else {
          if (cipher == null) {
            blockSize = getBlockSize(encryptionMode);
            cipher = Cipher.getInstance(encryptionMode);
          }
          // Encryption format: <iv><ciphertext>
          // Note a unique iv is generated per attribute
          cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, Utils.getRng());
          cipherText = ByteBuffer.allocate(blockSize + cipher.getOutputSize(plainText.remaining()));
          cipherText.position(blockSize);
          cipher.doFinal(plainText, cipherText);
          cipherText.flip();
          final byte[] iv = cipher.getIV();
          if (iv.length != blockSize) {
            throw new IllegalStateException(
                String.format(
                    "Generated IV length (%d) not equal to block size (%d)", iv.length, blockSize));
          }
          cipherText.put(iv);
          cipherText.rewind();
        }
        // Replace the plaintext attribute value with the encrypted content
        entry.setValue(new AttributeValue().withB(cipherText));
      }
    }
  }

  /**
   * Get the name of the DynamoDB field used to store the signature. Defaults to {@link
   * #DEFAULT_SIGNATURE_FIELD}.
   *
   * @return the name of the DynamoDB field used to store the signature
   */
  public String getSignatureFieldName() {
    return signatureFieldName;
  }

  /**
   * Set the name of the DynamoDB field used to store the signature.
   *
   * @param signatureFieldName
   */
  public void setSignatureFieldName(final String signatureFieldName) {
    this.signatureFieldName = signatureFieldName;
  }

  /**
   * Get the name of the DynamoDB field used to store metadata used by the DynamoDBEncryptedMapper.
   * Defaults to {@link #DEFAULT_METADATA_FIELD}.
   *
   * @return the name of the DynamoDB field used to store metadata used by the
   *     DynamoDBEncryptedMapper
   */
  public String getMaterialDescriptionFieldName() {
    return materialDescriptionFieldName;
  }

  /**
   * Set the name of the DynamoDB field used to store metadata used by the DynamoDBEncryptedMapper
   *
   * @param materialDescriptionFieldName
   */
  public void setMaterialDescriptionFieldName(final String materialDescriptionFieldName) {
    this.materialDescriptionFieldName = materialDescriptionFieldName;
  }

  /**
   * Marshalls the <code>description</code> into a ByteBuffer by outputting each key (modified
   * UTF-8) followed by its value (also in modified UTF-8).
   *
   * @param description
   * @return the description encoded as an AttributeValue with a ByteBuffer value
   * @see java.io.DataOutput#writeUTF(String)
   */
  protected static AttributeValue marshallDescription(Map<String, String> description) {
    try {
      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      DataOutputStream out = new DataOutputStream(bos);
      out.writeInt(CURRENT_VERSION);
      for (Map.Entry<String, String> entry : description.entrySet()) {
        byte[] bytes = entry.getKey().getBytes(UTF8);
        out.writeInt(bytes.length);
        out.write(bytes);
        bytes = entry.getValue().getBytes(UTF8);
        out.writeInt(bytes.length);
        out.write(bytes);
      }
      out.close();
      AttributeValue result = new AttributeValue();
      result.setB(ByteBuffer.wrap(bos.toByteArray()));
      return result;
    } catch (IOException ex) {
      // Due to the objects in use, an IOException is not possible.
      throw new RuntimeException("Unexpected exception", ex);
    }
  }

  public String getSigningAlgorithmHeader() {
    return signingAlgorithmHeader;
  }
  /** @see #marshallDescription(Map) */
  protected static Map<String, String> unmarshallDescription(AttributeValue attributeValue) {
    attributeValue.getB().mark();
    try (DataInputStream in =
        new DataInputStream(new ByteBufferInputStream(attributeValue.getB()))) {
      Map<String, String> result = new HashMap<String, String>();
      int version = in.readInt();
      if (version != CURRENT_VERSION) {
        throw new IllegalArgumentException("Unsupported description version");
      }

      String key, value;
      int keyLength, valueLength;
      try {
        while (in.available() > 0) {
          keyLength = in.readInt();
          byte[] bytes = new byte[keyLength];
          if (in.read(bytes) != keyLength) {
            throw new IllegalArgumentException("Malformed description");
          }
          key = new String(bytes, UTF8);
          valueLength = in.readInt();
          bytes = new byte[valueLength];
          if (in.read(bytes) != valueLength) {
            throw new IllegalArgumentException("Malformed description");
          }
          value = new String(bytes, UTF8);
          result.put(key, value);
        }
      } catch (EOFException eof) {
        throw new IllegalArgumentException("Malformed description", eof);
      }
      return result;
    } catch (IOException ex) {
      // Due to the objects in use, an IOException is not possible.
      throw new RuntimeException("Unexpected exception", ex);
    } finally {
      attributeValue.getB().reset();
    }
  }

  /**
   * @param encryptionContextOverrideOperator the nullable operator which will be used to override
   *     the EncryptionContext.
   * @see com.amazonaws.services.dynamodbv2.datamodeling.encryption.utils.EncryptionContextOperators
   */
  public final void setEncryptionContextOverrideOperator(
      Function<EncryptionContext, EncryptionContext> encryptionContextOverrideOperator) {
    this.encryptionContextOverrideOperator = encryptionContextOverrideOperator;
  }

  /**
   * @return the operator used to override the EncryptionContext
   * @see #setEncryptionContextOverrideOperator(Function)
   */
  public final Function<EncryptionContext, EncryptionContext>
      getEncryptionContextOverrideOperator() {
    return encryptionContextOverrideOperator;
  }

  private static byte[] toByteArray(ByteBuffer buffer) {
    buffer = buffer.duplicate();
    // We can only return the array directly if:
    // 1. The ByteBuffer exposes an array
    // 2. The ByteBuffer starts at the beginning of the array
    // 3. The ByteBuffer uses the entire array
    if (buffer.hasArray() && buffer.arrayOffset() == 0) {
      byte[] result = buffer.array();
      if (buffer.remaining() == result.length) {
        return result;
      }
    }

    byte[] result = new byte[buffer.remaining()];
    buffer.get(result);
    return result;
  }
}
