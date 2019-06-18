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
package com.amazonaws.services.dynamodbv2.testing.types;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBHashKey;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBRangeKey;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBTable;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DoNotTouch;

@DynamoDBTable(tableName = "TableName")
public class DoNotTouchField {
    @DynamoDBHashKey
    int hashKey;
    @DynamoDBRangeKey
    int rangeKey;
    @DoNotTouch
    int value;

    public DoNotTouchField() {
    }

    public DoNotTouchField(int hashKey, int rangeKey) {
        this.hashKey = hashKey;
        this.rangeKey = rangeKey;
    }

    public int getRangeKey() {
        return rangeKey;
    }

    public void setRangeKey(int rangeKey) {
        this.rangeKey = rangeKey;
    }

    public int getHashKey() {
        return hashKey;
    }

    public void setHashKey(int hashKey) {
        this.hashKey = hashKey;
    }

    public int getValue() {
        return value;
    }

    public void setValue(int value) {
        this.value = value;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + hashKey;
        result = prime * result + rangeKey;
        result = prime * result + value;
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        DoNotTouchField other = (DoNotTouchField) obj;
        if (hashKey != other.hashKey)
            return false;
        if (rangeKey != other.rangeKey)
            return false;
        if (value != other.value)
            return false;
        return true;
    }
}
