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
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBVersionAttribute;

import java.util.Arrays;
import java.util.Set;

@DynamoDBTable(tableName = "TableName")
public class BaseClass {
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + Arrays.hashCode(byteArrayValue);
        result = prime * result + hashKey;
        result = prime * result + ((intSet == null) ? 0 : intSet.hashCode());
        result = prime * result + intValue;
        result = prime * result + rangeKey;
        result = prime * result
                + ((stringSet == null) ? 0 : stringSet.hashCode());
        result = prime * result
                + ((stringValue == null) ? 0 : stringValue.hashCode());
        result = prime * result + Double.valueOf(doubleValue).hashCode();
        result = prime * result
                + ((doubleSet == null) ? 0 : doubleSet.hashCode());
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
        BaseClass other = (BaseClass) obj;
        if (!Arrays.equals(byteArrayValue, other.byteArrayValue))
            return false;
        if (hashKey != other.hashKey)
            return false;
        if (intSet == null) {
            if (other.intSet != null)
                return false;
        } else if (!intSet.equals(other.intSet))
            return false;
        if (intValue != other.intValue)
            return false;
        if (rangeKey != other.rangeKey)
            return false;
        if (stringSet == null) {
            if (other.stringSet != null)
                return false;
        } else if (!stringSet.equals(other.stringSet))
            return false;
        if (stringValue == null) {
            if (other.stringValue != null)
                return false;
        } else if (!stringValue.equals(other.stringValue))
            return false;
        if (doubleSet == null) {
            if (other.doubleSet != null)
                return false;
        } else if (!doubleSet.equals(other.doubleSet))
            return false;
        return true;
    }

    private int hashKey;
    private int rangeKey;
    private String stringValue;
    private int intValue;
    private byte[] byteArrayValue;
    private Set<String> stringSet;
    private Set<Integer> intSet;
    private Integer version;
    private double doubleValue;
    private Set<Double> doubleSet;

    @DynamoDBHashKey
    public int getHashKey() {
        return hashKey;
    }

    public void setHashKey(int hashKey) {
        this.hashKey = hashKey;
    }

    @DynamoDBRangeKey
    public int getRangeKey() {
        return rangeKey;
    }

    public void setRangeKey(int rangeKey) {
        this.rangeKey = rangeKey;
    }

    public String getStringValue() {
        return stringValue;
    }

    public void setStringValue(String stringValue) {
        this.stringValue = stringValue;
    }

    public int getIntValue() {
        return intValue;
    }

    public void setIntValue(int intValue) {
        this.intValue = intValue;
    }

    public byte[] getByteArrayValue() {
        return byteArrayValue;
    }

    public void setByteArrayValue(byte[] byteArrayValue) {
        this.byteArrayValue = byteArrayValue;
    }

    public Set<String> getStringSet() {
        return stringSet;
    }

    public void setStringSet(Set<String> stringSet) {
        this.stringSet = stringSet;
    }

    public Set<Integer> getIntSet() {
        return intSet;
    }

    public void setIntSet(Set<Integer> intSet) {
        this.intSet = intSet;
    }

    public Set<Double> getDoubleSet() {
        return doubleSet;
    }

    public void setDoubleSet(Set<Double> doubleSet) {
        this.doubleSet = doubleSet;
    }

    public double getDoubleValue() {
        return doubleValue;
    }

    public void setDoubleValue(double doubleValue) {
        this.doubleValue = doubleValue;
    }

    @DynamoDBVersionAttribute
    public Integer getVersion() {
        return version;
    }

    public void setVersion(Integer version) {
        this.version = version;
    }

    @Override
    public String toString() {
        return "BaseClass [hashKey=" + hashKey + ", rangeKey=" + rangeKey
                + ", stringValue=" + stringValue + ", intValue=" + intValue
                + ", byteArrayValue=" + Arrays.toString(byteArrayValue)
                + ", stringSet=" + stringSet + ", intSet=" + intSet
                + ", doubleSet=" + doubleSet + ", version=" + version + "]";
    }
}
