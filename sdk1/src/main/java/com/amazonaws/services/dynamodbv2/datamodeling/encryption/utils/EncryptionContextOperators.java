/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
package com.amazonaws.services.dynamodbv2.datamodeling.encryption.utils;

import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionContext;

import java.util.Map;
import java.util.function.UnaryOperator;

/**
 * Implementations of common operators for overriding the EncryptionContext
 */
public class EncryptionContextOperators {

    // Prevent instantiation
    private EncryptionContextOperators() {
    }

    /**
     * An operator for overriding EncryptionContext's table name for a specific DynamoDBEncryptor. If any table names or
     * the encryption context itself is null, then it returns the original EncryptionContext.
     *
     * @param originalTableName the name of the table that should be overridden in the Encryption Context
     * @param newTableName the table name that should be used in the Encryption Context
     * @return A UnaryOperator that produces a new EncryptionContext with the supplied table name
     */
    public static UnaryOperator<EncryptionContext> overrideEncryptionContextTableName(
            String originalTableName,
            String newTableName) {
        return encryptionContext -> {
            if (encryptionContext == null
                    || encryptionContext.getTableName() == null
                    || originalTableName == null
                    || newTableName == null) {
                return encryptionContext;
            }
            if (originalTableName.equals(encryptionContext.getTableName())) {
                return new EncryptionContext.Builder(encryptionContext).withTableName(newTableName).build();
            } else {
                return encryptionContext;
            }
        };
    }

    /**
     * An operator for mapping multiple table names in the Encryption Context to a new table name. If the table name for
     * a given EncryptionContext is missing, then it returns the original EncryptionContext. Similarly, it returns the
     * original EncryptionContext if the value it is overridden to is null, or if the original table name is null.
     *
     * @param tableNameOverrideMap a map specifying the names of tables that should be overridden,
     *                             and the values to which they should be overridden. If the given table name
     *                             corresponds to null, or isn't in the map, then the table name won't be overridden.
     * @return A UnaryOperator that produces a new EncryptionContext with the supplied table name
     */
    public static UnaryOperator<EncryptionContext> overrideEncryptionContextTableNameUsingMap(
            Map<String, String> tableNameOverrideMap) {
        return encryptionContext -> {
            if (tableNameOverrideMap == null || encryptionContext == null || encryptionContext.getTableName() == null) {
                return encryptionContext;
            }
            String newTableName = tableNameOverrideMap.get(encryptionContext.getTableName());
            if (newTableName != null) {
                return new EncryptionContext.Builder(encryptionContext).withTableName(newTableName).build();
            } else {
                return encryptionContext;
            }
        };
    }
}
