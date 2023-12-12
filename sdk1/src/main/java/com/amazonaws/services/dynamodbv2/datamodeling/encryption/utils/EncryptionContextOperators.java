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

/** Implementations of common operators for overriding the EncryptionContext */
public class EncryptionContextOperators {

  // Prevent instantiation
  private EncryptionContextOperators() {}

  /**
   * An operator for overriding EncryptionContext's table name for a specific DynamoDBEncryptor. If
   * any table names or the encryption context is null, it returns the original EncryptionContext.
   *
   * <p>The client automatically adds the current table name to the encryption context so it's bound
   * to the ciphertext. Use this method when the encryption context of encrypted table items
   * includes a different table name, such as when a table is backed up, or table items are
   * moved/copied to a different table. If you don't override the name of the current table with the
   * table name in the encryption context, decrypt fails. This override affects the encryption
   * context of all table items, including newly encrypted items.
   *
   * @param originalTableName Use this table name in the encryption context
   * @param currentTableName Override this table name in the encryption context
   * @return A UnaryOperator that produces a new EncryptionContext with the supplied table name
   */
  public static UnaryOperator<EncryptionContext> overrideEncryptionContextTableName(
      String originalTableName, String currentTableName) {
    return encryptionContext -> {
      if (encryptionContext == null
          || encryptionContext.getTableName() == null
          || originalTableName == null
          || currentTableName == null) {
        return encryptionContext;
      }
      if (originalTableName.equals(encryptionContext.getTableName())) {
        return new EncryptionContext.Builder(encryptionContext)
            .withTableName(currentTableName)
            .build();
      } else {
        return encryptionContext;
      }
    };
  }

  /**
   * An operator for mapping multiple table names in the Encryption Context to a new table name. If
   * the table name for a given EncryptionContext is missing, then it returns the original
   * EncryptionContext. Similarly, it returns the original EncryptionContext if the value it is
   * overridden to is null, or if the original table name is null.
   *
   * @param tableNameOverrideMap a map specifying the names of tables that should be overridden, and
   *     the values to which they should be overridden. If the given table name corresponds to null,
   *     or isn't in the map, then the table name won't be overridden.
   * @return A UnaryOperator that produces a new EncryptionContext with the supplied table name
   */
  public static UnaryOperator<EncryptionContext> overrideEncryptionContextTableNameUsingMap(
      Map<String, String> tableNameOverrideMap) {
    return encryptionContext -> {
      if (tableNameOverrideMap == null
          || encryptionContext == null
          || encryptionContext.getTableName() == null) {
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
