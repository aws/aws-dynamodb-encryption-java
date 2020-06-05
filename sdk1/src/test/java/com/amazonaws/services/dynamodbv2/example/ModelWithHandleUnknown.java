package com.amazonaws.services.dynamodbv2.example;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBAttribute;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBHashKey;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBTable;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DoNotEncrypt;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DoNotTouch;

//@HandleUnknownAttributes
@DynamoDBTable(tableName = "unknownDessert")
public class ModelWithHandleUnknown {
    @DynamoDBHashKey(attributeName = "partition_key")
    public String partitionKey() {
        return "";
    }

    @DynamoDBAttribute(attributeName = "DONUT")
    @DoNotTouch
    public String donut() {
        return "";
    }

    @DynamoDBAttribute(attributeName = "ICE_CREAM")
    @DoNotEncrypt
    public String iceCream() {
        return "";
    }

    @DynamoDBAttribute(attributeName = "CAKE")
    public String cake() {
        return "";
    }
}
