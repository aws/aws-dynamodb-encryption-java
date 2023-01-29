package software.amazon.awssdk.enhanced.dynamodb.internal.tags;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;
import software.amazon.awssdk.enhanced.dynamodb.AttributeValueType;
import software.amazon.awssdk.enhanced.dynamodb.TableMetadata;
import software.amazon.awssdk.enhanced.dynamodb.mapper.StaticAttributeTag;
import software.amazon.awssdk.enhanced.dynamodb.mapper.StaticTableMetadata;

public class EncryptedTag implements StaticAttributeTag {

    public static final String CUSTOM_METADATA_KEY_PREFIX = "Encryption:Encrypted";

    public static EncryptedTag create() {
        return new EncryptedTag();
    }

    @SuppressWarnings("unchecked")
    public static Set<String> resolve(TableMetadata tableMetadata) {
        return tableMetadata.customMetadataObject(CUSTOM_METADATA_KEY_PREFIX, Set.class)
                .orElseGet(HashSet::new);
    }

    @Override
    public Consumer<StaticTableMetadata.Builder> modifyMetadata(String attributeName, AttributeValueType attributeValueType) {
        return metadata -> metadata
                .addCustomMetadataObject(
                        CUSTOM_METADATA_KEY_PREFIX,
                        Collections.singleton(attributeName));
    }

}

