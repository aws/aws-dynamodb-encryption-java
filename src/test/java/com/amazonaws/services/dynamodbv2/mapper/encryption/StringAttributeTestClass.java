/*
 * Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except
 * in compliance with the License. A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package com.amazonaws.services.dynamodbv2.mapper.encryption;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBAttribute;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBHashKey;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBTable;

/**
 * Test domain class with a single string attribute and a string key
 */
@DynamoDBTable(tableName = "aws-java-sdk-util-crypto")
public class StringAttributeTestClass {

    private String key;
    private String stringAttribute;
    private String renamedAttribute;

    @DynamoDBHashKey
    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    @DynamoDBAttribute
    public String getStringAttribute() {
        return stringAttribute;
    }

    public void setStringAttribute(String stringAttribute) {
        this.stringAttribute = stringAttribute;
    }

    @DynamoDBAttribute(attributeName = "originalName")
    public String getRenamedAttribute() {
        return renamedAttribute;
    }

    public void setRenamedAttribute(String renamedAttribute) {
        this.renamedAttribute = renamedAttribute;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((key == null) ? 0 : key.hashCode());
        result = prime * result + ((renamedAttribute == null) ? 0 : renamedAttribute.hashCode());
        result = prime * result + ((stringAttribute == null) ? 0 : stringAttribute.hashCode());
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
        StringAttributeTestClass other = (StringAttributeTestClass) obj;
        if (key == null) {
            if (other.key != null)
                return false;
        } else if (!key.equals(other.key))
            return false;
        if (renamedAttribute == null) {
            if (other.renamedAttribute != null)
                return false;
        } else if (!renamedAttribute.equals(other.renamedAttribute))
            return false;
        if (stringAttribute == null) {
            if (other.stringAttribute != null)
                return false;
        } else if (!stringAttribute.equals(other.stringAttribute))
            return false;
        return true;
    }

}
