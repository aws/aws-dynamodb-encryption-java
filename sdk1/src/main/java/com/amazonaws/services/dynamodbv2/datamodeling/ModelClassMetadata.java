package com.amazonaws.services.dynamodbv2.datamodeling;

import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionFlags;

import java.util.Map;
import java.util.Set;

interface ModelClassMetadata {
    public Map<String, Set<EncryptionFlags>> getEncryptionFlags();

    public boolean getDoNotTouch();

    public Set<EncryptionFlags> getUnknownAttributeBehavior();
}
