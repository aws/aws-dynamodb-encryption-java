package com.amazonaws.services.dynamodbv2.example;

import com.amazonaws.services.dynamodbv2.datamodeling.AttributeEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.CryptoMapperMetaData;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DynamoDBEncryptor;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionFlags;
import com.google.common.collect.ImmutableSet;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.Set;

public class ClientTest {
    AttributeEncryptor attributeEncryptor = new AttributeEncryptor((DynamoDBEncryptor) null);

    @Test
    public void defaultClassSemantics() {
        CryptoMapperMetaData metaData = attributeEncryptor.metaData(ModelWithDefaultSemantics.class);

        Assert.assertEquals(
                metaData.attributes(),
                ImmutableSet.of("CAKE", "ICE_CREAM", "DONUT"));

        Assert.assertEquals(
                metaData.attributesWithSemantic(EncryptionFlags.SIGN),
                ImmutableSet.of("CAKE", "ICE_CREAM"));
        Assert.assertEquals(
                metaData.attributesWithSemantic(EncryptionFlags.ENCRYPT),
                ImmutableSet.of("CAKE"));
        Assert.assertEquals(
                metaData.attributesWithoutSemantics(),
                ImmutableSet.of("DONUT"));

        Assert.assertEquals(
                ImmutableSet.of(EncryptionFlags.ENCRYPT, EncryptionFlags.SIGN),
                metaData.attributeSemantics("CAKE"));

    }

    @Test
    public void handleUnknownClassSemantics() {
        CryptoMapperMetaData metaData = attributeEncryptor.metaData(ModelWithHandleUnknown.class);

        Assert.assertEquals(
                metaData.attributes(),
                ImmutableSet.of("CAKE", "ICE_CREAM", "DONUT"));

        Assert.assertEquals(
                metaData.attributesWithSemantic(EncryptionFlags.SIGN),
                ImmutableSet.of("CAKE", "ICE_CREAM"));
        Assert.assertEquals(
                metaData.attributesWithSemantic(EncryptionFlags.ENCRYPT),
                ImmutableSet.of("CAKE"));
        Assert.assertEquals(
                metaData.attributesWithoutSemantics(),
                ImmutableSet.of());

        Assert.assertEquals(
                ImmutableSet.of(EncryptionFlags.ENCRYPT, EncryptionFlags.SIGN),
                metaData.attributeSemantics("CAKE"));
    }
}
