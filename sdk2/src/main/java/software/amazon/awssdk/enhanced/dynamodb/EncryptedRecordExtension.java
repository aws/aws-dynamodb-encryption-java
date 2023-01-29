package software.amazon.awssdk.enhanced.dynamodb;


import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import software.amazon.awssdk.enhanced.dynamodb.encryption.DynamoDBEncryptor;
import software.amazon.awssdk.enhanced.dynamodb.encryption.EncryptionContext;
import software.amazon.awssdk.enhanced.dynamodb.encryption.EncryptionFlags;
import software.amazon.awssdk.enhanced.dynamodb.encryption.providers.EncryptionMaterialsProvider;
import software.amazon.awssdk.enhanced.dynamodb.extensions.ReadModification;
import software.amazon.awssdk.enhanced.dynamodb.extensions.WriteModification;
import software.amazon.awssdk.enhanced.dynamodb.internal.tags.EncryptedTag;
import software.amazon.awssdk.enhanced.dynamodb.internal.tags.SignedTag;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

public class EncryptedRecordExtension implements DynamoDbEnhancedClientExtension {

    private static final String METADATA_KEY_PREFIX = "EncryptedRecordExtension:";

    private final DynamoDBEncryptor encryptor;

    protected EncryptedRecordExtension(final DynamoDBEncryptor encryptor) {
        this.encryptor = encryptor;
    }

    protected EncryptedRecordExtension(final EncryptionMaterialsProvider encryptionMaterialsProvider) {
        encryptor = DynamoDBEncryptor.getInstance(encryptionMaterialsProvider);
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * This hook is called just before an operation is going to write data to the database. The extension that
     * implements this method can choose to transform the item itself, or add a condition to the write operation
     * or both.
     *
     * @param context The {@link DynamoDbExtensionContext.BeforeWrite} context containing the state of the execution.
     * @return A {@link WriteModification} object that can alter the behavior of the write operation.
     */
    public WriteModification beforeWrite(DynamoDbExtensionContext.BeforeWrite context) {
        final Map<String, AttributeValue> attributeValues = context.items();
        final Map<String, Set<EncryptionFlags>> attributeFlags =
                buildEncryptionFlags(context.tableMetadata());

        // If no attributes have been flagged, there is nothing to do
        if (attributeFlags.isEmpty()) {
            return WriteModification.builder()
                    .transformedItem(attributeValues)
                    .build();
        }

        try {
            return WriteModification.builder()
                    .transformedItem(encryptor.encryptRecord(
                            attributeValues, attributeFlags, paramsToContext(context)))
                    .build();

        } catch (Exception ex) {
            throw new EncryptionException(ex);
        }

    }

    /**
     * This hook is called just after an operation that has read data from the database. The extension that
     * implements this method can choose to transform the item, and then it is the transformed item that will be
     * mapped back to the application instead of the item that was actually read from the database.
     *
     * @param context The {@link DynamoDbExtensionContext.AfterRead} context containing the state of the execution.
     * @return A {@link ReadModification} object that can alter the results of a read operation.
     */
    public ReadModification afterRead(DynamoDbExtensionContext.AfterRead context) {
        final Map<String, AttributeValue> attributeValues = context.items();
        final Map<String, Set<EncryptionFlags>> attributeFlags =
                buildEncryptionFlags(context.tableMetadata());


        // If no attributes have been flagged, there is nothing to do
        if (attributeFlags.isEmpty()) {
            return ReadModification.builder()
                    .transformedItem(attributeValues)
                    .build();
        }

        try {
            return ReadModification.builder()
                    .transformedItem(
                            encryptor.decryptRecord(
                                    attributeValues, attributeFlags, paramsToContext(context)))
                    .build();
        } catch (Exception ex) {
            throw new EncryptionException(ex);
        }

    }

    public DynamoDBEncryptor getEncryptor() {
        return encryptor;
    }


    private static EncryptionContext paramsToContext(DynamoDbExtensionContext.Context ctx) {

        return new EncryptionContext.Builder()
                .withHashKeyName(ctx.tableMetadata().primaryPartitionKey())
                .withRangeKeyName(ctx.tableMetadata().primarySortKey().orElse(null))
                .withTableName(ctx.operationContext().tableName())
                .withAttributeValues(ctx.items())
                .build();
    }

    private Map<String, Set<EncryptionFlags>> buildEncryptionFlags(TableMetadata metadata) {
        final Map<String, Set<EncryptionFlags>> flags = new HashMap<>();
        SignedTag.resolve(metadata)
                .forEach(a -> flags.put(a, EnumSet.of(EncryptionFlags.SIGN)));
        EncryptedTag.resolve(metadata)
                .forEach(a -> {
                        if (flags.containsKey(a)) {
                            flags.get(a).add(EncryptionFlags.ENCRYPT);
                        } else {
                            flags.put(a, EnumSet.of(EncryptionFlags.ENCRYPT));
                        }
                });

        return flags;
    }

    public static final class Builder {

        private EncryptionMaterialsProvider encryptionMaterialsProvider;

        private Builder() {
        }

        public Builder encryptionMaterialsProvider(EncryptionMaterialsProvider encryptionMaterialsProvider) {
            this.encryptionMaterialsProvider = encryptionMaterialsProvider;
            return this;
        }

        public EncryptedRecordExtension build() {
            if (this.encryptionMaterialsProvider == null) {
                throw new EncryptionException("You must provide an encryption materials provider.");
            }
            return new EncryptedRecordExtension(encryptionMaterialsProvider);
        }
    }

}
