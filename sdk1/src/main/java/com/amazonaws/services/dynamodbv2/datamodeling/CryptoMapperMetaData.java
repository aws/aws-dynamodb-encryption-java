package com.amazonaws.services.dynamodbv2.datamodeling;

import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionFlags;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class CryptoMapperMetaData implements ModelClassMetadata {
    private final Map<String, Set<EncryptionFlags>> encryptionFlags;
    private final boolean doNotTouch;
    private final Set<EncryptionFlags> unknownAttributeBehavior;

    public CryptoMapperMetaData(
            Map<String, Set<EncryptionFlags>> encryptionFlags,
            boolean doNotTouch,
            Set<EncryptionFlags> unknownAttributeBehavior
    ) {
        this.encryptionFlags = encryptionFlags;
        this.doNotTouch = doNotTouch;
        this.unknownAttributeBehavior = unknownAttributeBehavior;
    }

    public Map<String, Set<EncryptionFlags>> getEncryptionFlags() {
        return encryptionFlags;
    }

    public boolean getDoNotTouch() {
        return doNotTouch;
    }

    public Set<EncryptionFlags> getUnknownAttributeBehavior() {
        return unknownAttributeBehavior;
    }

    public Set<String> attributes() {
        return encryptionFlags.keySet();
    }

    public Set<String> attributesWithSemantic(EncryptionFlags flag) {
        return encryptionFlags
                .entrySet()
                .stream()
                .filter(entry -> entry.getValue().contains(flag))
                .map(entry -> entry.getKey())
                .collect(Collectors.toSet());
    }

    public Set<String> attributesWithoutSemantics() {
        return encryptionFlags
                .entrySet()
                .stream()
                .filter(entry -> entry.getValue().isEmpty())
                .map(entry -> entry.getKey())
                .collect(Collectors.toSet());
    }

    public Set<EncryptionFlags> attributeSemantics(String attributeName) {
        return encryptionFlags.getOrDefault(attributeName, unknownAttributeBehavior);
    }
}
