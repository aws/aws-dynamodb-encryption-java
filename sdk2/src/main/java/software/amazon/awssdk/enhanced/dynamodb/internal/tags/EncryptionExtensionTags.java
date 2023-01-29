package software.amazon.awssdk.enhanced.dynamodb.internal.tags;

import software.amazon.awssdk.enhanced.dynamodb.encryption.annotations.Encrypted;
import software.amazon.awssdk.enhanced.dynamodb.encryption.annotations.Signed;
import software.amazon.awssdk.enhanced.dynamodb.mapper.StaticAttributeTag;

public final class EncryptionExtensionTags {

    public static StaticAttributeTag attributeTagFor(Encrypted annotation) {
        return EncryptedTag.create();
    }

    public static StaticAttributeTag attributeTagFor(Signed annotation) {
        return SignedTag.create();
    }

    public static StaticAttributeTag encrypted() {
        return EncryptedTag.create();
    }

    public static StaticAttributeTag signed() {
        return SignedTag.create();
    }
}
