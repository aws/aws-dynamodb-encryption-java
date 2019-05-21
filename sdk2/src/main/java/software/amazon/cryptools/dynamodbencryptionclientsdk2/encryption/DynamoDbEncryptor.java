/*
 * Copyright 2014-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
package software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.DynamoDbEncryptionClient;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.DynamoDbEncryptionConfiguration;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.EncryptionAction;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption.exceptions.DynamoDbEncryptionException;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption.materials.DecryptionMaterials;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption.materials.EncryptionMaterials;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption.providers.EncryptionMaterialsProvider;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.internal.AttributeValueMarshaller;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.internal.ByteBufferInputStream;
import software.amazon.cryptools.dynamodbencryptionclientsdk2.internal.Utils;

/**
 * The low-level API for performing crypto operations on the record attributes.
 * 
 * @author Greg Rubin 
 */
public class DynamoDbEncryptor implements DynamoDbEncryptionClient {
    private static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String DEFAULT_METADATA_FIELD = "*amzn-ddb-map-desc*";
    private static final String DEFAULT_SIGNATURE_FIELD = "*amzn-ddb-map-sig*";
    private static final String DEFAULT_DESCRIPTION_BASE = "amzn-ddb-map-"; // Same as the Mapper
    private static final Charset UTF8 = Charset.forName("UTF-8");
    private static final String SYMMETRIC_ENCRYPTION_MODE = "/CBC/PKCS5Padding";
    private static final ConcurrentHashMap<String, Integer> BLOCK_SIZE_CACHE = new ConcurrentHashMap<>();
    private static final Function<String, Integer> BLOCK_SIZE_CALCULATOR = (transformation) -> {
        try {
            final Cipher c = Cipher.getInstance(transformation);
            return c.getBlockSize();
        } catch (final GeneralSecurityException ex) {
            throw new IllegalArgumentException("Algorithm does not exist", ex);
        }
    };

    private static final int CURRENT_VERSION = 0;

    // Static map used to convert an EncryptionAction into a corresponding set of EncryptionFlags
    private static final Map<EncryptionAction, Set<EncryptionFlags>> ENCRYPTION_ACTION_TO_FLAGS_MAP;
    static {
        Map<EncryptionAction, Set<EncryptionFlags>> encrytionActionToFlagsMap = new HashMap<>();
        encrytionActionToFlagsMap.put(EncryptionAction.DO_NOTHING, Collections.emptySet());
        encrytionActionToFlagsMap.put(EncryptionAction.SIGN_ONLY, Collections.singleton(EncryptionFlags.SIGN));
        encrytionActionToFlagsMap.put(EncryptionAction.ENCRYPT_AND_SIGN,
            Collections.unmodifiableSet(new HashSet<>(Arrays.asList(EncryptionFlags.SIGN, EncryptionFlags.ENCRYPT))));
        ENCRYPTION_ACTION_TO_FLAGS_MAP = Collections.unmodifiableMap(encrytionActionToFlagsMap);
    }

    private String signatureFieldName = DEFAULT_SIGNATURE_FIELD;
    private String materialDescriptionFieldName = DEFAULT_METADATA_FIELD;
    
    private EncryptionMaterialsProvider encryptionMaterialsProvider;
    private final String descriptionBase;
    private final String symmetricEncryptionModeHeader;
    private final String signingAlgorithmHeader;
    
    static final String DEFAULT_SIGNING_ALGORITHM_HEADER = DEFAULT_DESCRIPTION_BASE + "signingAlg";

    private Function<EncryptionContext, EncryptionContext> encryptionContextOverrideOperator;

    protected DynamoDbEncryptor(EncryptionMaterialsProvider provider, String descriptionBase) {
        this.encryptionMaterialsProvider = provider;
        this.descriptionBase = descriptionBase;
        symmetricEncryptionModeHeader = this.descriptionBase + "sym-mode";
        signingAlgorithmHeader = this.descriptionBase + "signingAlg";
    }

    protected DynamoDbEncryptor(EncryptionMaterialsProvider provider) {
        this(provider, DEFAULT_DESCRIPTION_BASE);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private EncryptionMaterialsProvider encryptionMaterialsProvider;

        public Builder encryptionMaterialsProvider(EncryptionMaterialsProvider encryptionMaterialsProvider) {
            this.encryptionMaterialsProvider = encryptionMaterialsProvider;
            return this;
        }

        public DynamoDbEncryptor build() {
            if (encryptionMaterialsProvider == null) {
                throw new IllegalArgumentException("A DynamoDbEncryptor cannot be built without an "
                                                   + "EncryptionMaterialsProvider");
            }

            return new DynamoDbEncryptor(encryptionMaterialsProvider);
        }
    }

    @Override
    public Map<String, AttributeValue> encryptRecord(Map<String, AttributeValue> record,
                                                     DynamoDbEncryptionConfiguration configuration) {

        validateParameters(record, configuration);
        return internalEncryptRecord(record,
                                     getEncryptionFlagsFromConfiguration(record, configuration),
                                     configuration.getEncryptionContext());
    }

    @Override
    public Map<String, AttributeValue> decryptRecord(Map<String, AttributeValue> record,
                                                     DynamoDbEncryptionConfiguration configuration) {

        validateParameters(record, configuration);
        return internalDecryptRecord(record,
                                     getEncryptionFlagsFromConfiguration(record, configuration),
                                     configuration.getEncryptionContext());
    }

    private void validateParameters(Map<String, AttributeValue> record,
                                    DynamoDbEncryptionConfiguration configuration) {
        if (record == null) {
            throw new IllegalArgumentException("AttributeValues must not be null");
        }
        if (configuration == null) {
            throw new IllegalArgumentException("DynamoDbEncryptionConfiguration must not be null");
        }
        if (configuration.getEncryptionContext() == null) {
            throw new IllegalArgumentException("DynamoDbEncryptionConfiguration's EncryptionContext must not be null");
        }
        if (configuration.getDefaultEncryptionAction() == null) {
            throw new IllegalArgumentException("DynamoDbEncryptionConfiguration's DefaultEncryptionAction must not be"
                                               + " null");
        }
    }


    private Map<String, Set<EncryptionFlags>> getEncryptionFlagsFromConfiguration(
        Map<String, AttributeValue> record,
        DynamoDbEncryptionConfiguration configuration) {

        return record.keySet()
                     .stream()
                     // Do not let attributes created by the encryption library participate in encrypting or signing
                     .filter(key -> !key.equals(getMaterialDescriptionFieldName())
                                    && !key.equals(getSignatureFieldName()))
                     .collect(Collectors.toMap(Function.identity(), key -> {
                         EncryptionAction encryptionAction = configuration.getEncryptionActionOverrides().get(key);

                         if (encryptionAction == null) {
                             encryptionAction = configuration.getDefaultEncryptionAction();
                         }

                         return getEncryptionFlagsForAction(encryptionAction);
                     }));
    }

    private Map<String, AttributeValue> internalDecryptRecord(
            Map<String, AttributeValue> itemAttributes,
            Map<String, Set<EncryptionFlags>> attributeFlags,
            EncryptionContext context) {
        if (attributeFlags.isEmpty()) {
            return itemAttributes;
        }
        // Copy to avoid changing anyone elses objects
        itemAttributes = new HashMap<>(itemAttributes);
        
        Map<String, String> materialDescription = Collections.emptyMap();
        DecryptionMaterials materials;
        SecretKey decryptionKey;

        DynamoDbSigner signer = DynamoDbSigner.getInstance(DEFAULT_SIGNATURE_ALGORITHM, Utils.getRng());

        if (itemAttributes.containsKey(materialDescriptionFieldName)) {
            materialDescription = unmarshallDescription(itemAttributes.get(materialDescriptionFieldName));
        }
        // Copy the material description and attribute values into the context
        context = context.toBuilder()
            .materialDescription(materialDescription)
            .attributeValues(itemAttributes)
            .build();

        Function<EncryptionContext, EncryptionContext> encryptionContextOverrideOperator = getEncryptionContextOverrideOperator();
        if (encryptionContextOverrideOperator != null) {
            context = encryptionContextOverrideOperator.apply(context);
        }

        materials = encryptionMaterialsProvider.getDecryptionMaterials(context);
        decryptionKey = materials.getDecryptionKey();
        if (materialDescription.containsKey(signingAlgorithmHeader)) {
            String signingAlg = materialDescription.get(signingAlgorithmHeader);
            signer = DynamoDbSigner.getInstance(signingAlg, Utils.getRng());
        }
        
        ByteBuffer signature;
        if (!itemAttributes.containsKey(signatureFieldName) || itemAttributes.get(signatureFieldName).b() == null) {
            signature = ByteBuffer.allocate(0);
        } else {
            signature = itemAttributes.get(signatureFieldName).b().asByteBuffer();
        }
        itemAttributes.remove(signatureFieldName);

        String associatedData = "TABLE>" + context.getTableName() + "<TABLE";

        try {
            signer.verifySignature(itemAttributes, attributeFlags, associatedData.getBytes(UTF8),
                                   materials.getVerificationKey(), signature);
            itemAttributes.remove(materialDescriptionFieldName);

            actualDecryption(itemAttributes, attributeFlags, decryptionKey, materialDescription);
        } catch (GeneralSecurityException e) {
            throw new DynamoDbEncryptionException("A general security exception was thrown during the decryption of a"
                                                  + " record", e);
        }
        return itemAttributes;
    }

    private Map<String, AttributeValue> internalEncryptRecord(
            Map<String, AttributeValue> itemAttributes,
            Map<String, Set<EncryptionFlags>> attributeFlags,
            EncryptionContext context) {
        if (attributeFlags.isEmpty()) {
            return itemAttributes;
        }
        // Copy to avoid changing anyone elses objects
        itemAttributes = new HashMap<>(itemAttributes);

        // Copy the attribute values into the context
        context = context.toBuilder()
            .attributeValues(itemAttributes)
            .build();

        Function<EncryptionContext, EncryptionContext> encryptionContextOverrideOperator =
                getEncryptionContextOverrideOperator();
        if (encryptionContextOverrideOperator != null) {
            context = encryptionContextOverrideOperator.apply(context);
        }

        EncryptionMaterials materials = encryptionMaterialsProvider.getEncryptionMaterials(context);
        // We need to copy this because we modify it to record other encryption details
        Map<String, String> materialDescription = new HashMap<>(
            materials.getMaterialDescription());
        SecretKey encryptionKey = materials.getEncryptionKey();

        try {
            actualEncryption(itemAttributes, attributeFlags, materialDescription, encryptionKey);

            // The description must be stored after encryption because its data
            // is necessary for proper decryption.
            final String signingAlgo = materialDescription.get(signingAlgorithmHeader);
            DynamoDbSigner signer;
            if (signingAlgo != null) {
                signer = DynamoDbSigner.getInstance(signingAlgo, Utils.getRng());
            } else {
                signer = DynamoDbSigner.getInstance(DEFAULT_SIGNATURE_ALGORITHM, Utils.getRng());
            }

            if (materials.getSigningKey() instanceof PrivateKey) {
                materialDescription.put(signingAlgorithmHeader, signer.getSigningAlgorithm());
            }
            if (! materialDescription.isEmpty()) {
                itemAttributes.put(materialDescriptionFieldName, marshallDescription(materialDescription));
            }

            String associatedData = "TABLE>" + context.getTableName() + "<TABLE";
            byte[] signature = signer.calculateSignature(itemAttributes, attributeFlags,
                                                         associatedData.getBytes(UTF8), materials.getSigningKey());

            AttributeValue signatureAttribute = AttributeValue.builder().b(SdkBytes.fromByteArray(signature)).build();
            itemAttributes.put(signatureFieldName, signatureAttribute);
        } catch (GeneralSecurityException e) {
            throw new DynamoDbEncryptionException("A general security exception was thrown during the encryption of a "
                                                  + "record", e);
        }

        return itemAttributes;
    }
    
    private void actualDecryption(Map<String, AttributeValue> itemAttributes,
            Map<String, Set<EncryptionFlags>> attributeFlags, SecretKey encryptionKey,
            Map<String, String> materialDescription) throws GeneralSecurityException {
        final String encryptionMode = encryptionKey != null ?  encryptionKey.getAlgorithm() +
                    materialDescription.get(symmetricEncryptionModeHeader) : null;
        Cipher cipher = null;
        int blockSize = -1;

        for (Map.Entry<String, AttributeValue> entry: itemAttributes.entrySet()) {
            Set<EncryptionFlags> flags = attributeFlags.get(entry.getKey());
            if (flags != null && flags.contains(EncryptionFlags.ENCRYPT)) {
                if (!flags.contains(EncryptionFlags.SIGN)) {
                    throw new IllegalArgumentException("All encrypted fields must be signed. Bad field: " + entry.getKey());
                }
                ByteBuffer plainText;
                ByteBuffer cipherText = entry.getValue().b().asByteBuffer();
                cipherText.rewind();
                if (encryptionKey instanceof DelegatedKey) {
                    plainText = ByteBuffer.wrap(((DelegatedKey)encryptionKey).decrypt(toByteArray(cipherText), null, encryptionMode));
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

    private static int getBlockSize(final String encryptionMode) {
        return BLOCK_SIZE_CACHE.computeIfAbsent(encryptionMode, BLOCK_SIZE_CALCULATOR);
    }

    /**
     * This method has the side effect of replacing the plaintext
     * attribute-values of "itemAttributes" with ciphertext attribute-values
     * (which are always in the form of ByteBuffer) as per the corresponding
     * attribute flags.
     */
    private void actualEncryption(Map<String, AttributeValue> itemAttributes,
            Map<String, Set<EncryptionFlags>> attributeFlags,
            Map<String, String> materialDescription,
            SecretKey encryptionKey) throws GeneralSecurityException {
        String encryptionMode = null;
        if (encryptionKey != null) {
            materialDescription.put(this.symmetricEncryptionModeHeader,
                    SYMMETRIC_ENCRYPTION_MODE);
            encryptionMode = encryptionKey.getAlgorithm() + SYMMETRIC_ENCRYPTION_MODE;
        }
        Cipher cipher = null;
        int blockSize = -1;

        for (Map.Entry<String, AttributeValue> entry: itemAttributes.entrySet()) {
            Set<EncryptionFlags> flags = attributeFlags.get(entry.getKey());
            if (flags != null && flags.contains(EncryptionFlags.ENCRYPT)) {
                if (!flags.contains(EncryptionFlags.SIGN)) {
                    throw new IllegalArgumentException("All encrypted fields must be signed. Bad field: " + entry.getKey());
                }
                ByteBuffer plainText = AttributeValueMarshaller.marshall(entry.getValue());
                plainText.rewind();
                ByteBuffer cipherText;
                if (encryptionKey instanceof DelegatedKey) {
                    DelegatedKey dk = (DelegatedKey) encryptionKey;
                    cipherText = ByteBuffer.wrap(
                            dk.encrypt(toByteArray(plainText), null, encryptionMode));
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
                        throw new IllegalStateException(String.format("Generated IV length (%d) not equal to block size (%d)",
                                iv.length, blockSize));
                    }
                    cipherText.put(iv);
                    cipherText.rewind();
                }
                // Replace the plaintext attribute value with the encrypted content
                entry.setValue(AttributeValue.builder().b(SdkBytes.fromByteBuffer(cipherText)).build());
            }
        }
    }
    
    /**
     * Get the name of the DynamoDB field used to store the signature.
     * Defaults to {@link #DEFAULT_SIGNATURE_FIELD}.
     *
     * @return the name of the DynamoDB field used to store the signature
     */
    String getSignatureFieldName() {
        return signatureFieldName;
    }

    /**
     * Set the name of the DynamoDB field used to store the signature.
     *
     * @param signatureFieldName
     */
    void setSignatureFieldName(final String signatureFieldName) {
        this.signatureFieldName = signatureFieldName;
    }

    /**
     * Get the name of the DynamoDB field used to store metadata used by the
     * DynamoDBEncryptedMapper. Defaults to {@link #DEFAULT_METADATA_FIELD}.
     *
     * @return the name of the DynamoDB field used to store metadata used by the
     *         DynamoDBEncryptedMapper
     */
    String getMaterialDescriptionFieldName() {
        return materialDescriptionFieldName;
    }

    /**
     * Set the name of the DynamoDB field used to store metadata used by the
     * DynamoDBEncryptedMapper
     *
     * @param materialDescriptionFieldName
     */
    void setMaterialDescriptionFieldName(final String materialDescriptionFieldName) {
        this.materialDescriptionFieldName = materialDescriptionFieldName;
    }
    
    /**
     * Marshalls the <code>description</code> into a ByteBuffer by outputting
     * each key (modified UTF-8) followed by its value (also in modified UTF-8).
     *
     * @param description
     * @return the description encoded as an AttributeValue with a ByteBuffer value
     * @see java.io.DataOutput#writeUTF(String)
     */
    private static AttributeValue marshallDescription(Map<String, String> description) {
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
            return AttributeValue.builder().b(SdkBytes.fromByteArray(bos.toByteArray())).build();
        } catch (IOException ex) {
            // Due to the objects in use, an IOException is not possible.
            throw new RuntimeException("Unexpected exception", ex);
        }
    }

    /**
     * @see #marshallDescription(Map)
     */
    private static Map<String, String> unmarshallDescription(AttributeValue attributeValue) {
        try (DataInputStream in = new DataInputStream(
                    new ByteBufferInputStream(attributeValue.b().asByteBuffer())) ) {
            Map<String, String> result = new HashMap<>();
            int version = in.readInt();
            if (version != CURRENT_VERSION) {
                throw new IllegalArgumentException("Unsupported description version");
            }

            String key, value;
            int keyLength, valueLength;
            try {
                while(in.available() > 0) {
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
        }
    }

    /**
     * @param encryptionContextOverrideOperator  the nullable operator which will be used to override
     *                                           the EncryptionContext.
     * @see EncryptionContextOperators
     */
    void setEncryptionContextOverrideOperator(
        Function<EncryptionContext, EncryptionContext> encryptionContextOverrideOperator) {
        this.encryptionContextOverrideOperator = encryptionContextOverrideOperator;
    }

    /**
     * @return the operator used to override the EncryptionContext
     * @see #setEncryptionContextOverrideOperator(Function)
     */
    private Function<EncryptionContext, EncryptionContext> getEncryptionContextOverrideOperator() {
        return encryptionContextOverrideOperator;
    }

    private static Set<EncryptionFlags> getEncryptionFlagsForAction(EncryptionAction encryptionAction) {
        Set<EncryptionFlags> encryptionFlags = ENCRYPTION_ACTION_TO_FLAGS_MAP.get(encryptionAction);

        if (encryptionFlags == null) {
            throw new RuntimeException("Unrecognized EncryptionAction : " + encryptionAction.name());
        }

        return encryptionFlags;
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
