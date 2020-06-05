package com.amazonaws.services.dynamodbv2.example;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBAttribute;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBHashKey;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBTable;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DoNotEncrypt;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DoNotTouch;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.HandleUnknownAttributes;

@DynamoDBTable(tableName = "defaultDessert")
public class ModelWithDefaultSemantics {
    @DynamoDBHashKey(attributeName = "partition_key")
    public String partitionKey() {
        return "";
    }

    @DynamoDBAttribute(attributeName = "DONUT")
    @DoNotTouch
    public String getDonut() {
        return "";
    }

    @DynamoDBAttribute(attributeName = "ICE_CREAM")
    @DoNotEncrypt
    public String getIceCream() {
        return "";
    }

    @DynamoDBAttribute(attributeName = "CAKE")
    public String getCake() {
        return "";
    }
}

