/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
package software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption;

import static org.testng.AssertJUnit.assertEquals;
import static software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption.EncryptionContextOperators.overrideEncryptionContextTableName;
import static software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption.EncryptionContextOperators.overrideEncryptionContextTableNameUsingMap;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.testng.annotations.Test;

public class EncryptionContextOperatorsTest {

    @Test
    public void testCreateEncryptionContextTableNameOverride_expectedOverride() {
        Function<EncryptionContext, EncryptionContext> myNewTableName = overrideEncryptionContextTableName("OriginalTableName", "MyNewTableName");

        EncryptionContext context = EncryptionContext.builder().tableName("OriginalTableName").build();

        EncryptionContext newContext = myNewTableName.apply(context);

        assertEquals("OriginalTableName", context.getTableName());
        assertEquals("MyNewTableName", newContext.getTableName());
    }

    /**
     * Some pretty clear repetition in null cases. May make sense to replace with data providers or parameterized
     * classes for null cases
     */
    @Test
    public void testNullCasesCreateEncryptionContextTableNameOverride_nullOriginalTableName() {
        assertEncryptionContextUnchanged(EncryptionContext.builder().tableName("example").build(),
                null,
                "MyNewTableName");
    }

    @Test
    public void testCreateEncryptionContextTableNameOverride_differentOriginalTableName() {
        assertEncryptionContextUnchanged(EncryptionContext.builder().tableName("example").build(),
                "DifferentTableName",
                "MyNewTableName");
    }

    @Test
    public void testNullCasesCreateEncryptionContextTableNameOverride_nullEncryptionContext() {
        assertEncryptionContextUnchanged(null,
                "DifferentTableName",
                "MyNewTableName");
    }

    @Test
    public void testCreateEncryptionContextTableNameOverrideMap_expectedOverride() {
        Map<String, String> tableNameOverrides = new HashMap<>();
        tableNameOverrides.put("OriginalTableName", "MyNewTableName");


        Function<EncryptionContext, EncryptionContext> nameOverrideMap =
                overrideEncryptionContextTableNameUsingMap(tableNameOverrides);

        EncryptionContext context = EncryptionContext.builder().tableName("OriginalTableName").build();

        EncryptionContext newContext = nameOverrideMap.apply(context);

        assertEquals("OriginalTableName", context.getTableName());
        assertEquals("MyNewTableName", newContext.getTableName());
    }

    @Test
    public void testCreateEncryptionContextTableNameOverrideMap_multipleOverrides() {
        Map<String, String> tableNameOverrides = new HashMap<>();
        tableNameOverrides.put("OriginalTableName1", "MyNewTableName1");
        tableNameOverrides.put("OriginalTableName2", "MyNewTableName2");


        Function<EncryptionContext, EncryptionContext> overrideOperator =
                overrideEncryptionContextTableNameUsingMap(tableNameOverrides);

        EncryptionContext context = EncryptionContext.builder().tableName("OriginalTableName1").build();

        EncryptionContext newContext = overrideOperator.apply(context);

        assertEquals("OriginalTableName1", context.getTableName());
        assertEquals("MyNewTableName1", newContext.getTableName());

        EncryptionContext context2 = EncryptionContext.builder().tableName("OriginalTableName2").build();

        EncryptionContext newContext2 = overrideOperator.apply(context2);

        assertEquals("OriginalTableName2", context2.getTableName());
        assertEquals("MyNewTableName2", newContext2.getTableName());

    }


    @Test
    public void testNullCasesCreateEncryptionContextTableNameOverrideFromMap_nullEncryptionContextTableName() {
        Map<String, String> tableNameOverrides = new HashMap<>();
        tableNameOverrides.put("DifferentTableName", "MyNewTableName");
        assertEncryptionContextUnchangedFromMap(EncryptionContext.builder().build(),
                tableNameOverrides);
    }

    @Test
    public void testNullCasesCreateEncryptionContextTableNameOverrideFromMap_nullEncryptionContext() {
        Map<String, String> tableNameOverrides = new HashMap<>();
        tableNameOverrides.put("DifferentTableName", "MyNewTableName");
        assertEncryptionContextUnchangedFromMap(null,
                tableNameOverrides);
    }


    @Test
    public void testNullCasesCreateEncryptionContextTableNameOverrideFromMap_nullOriginalTableName() {
        Map<String, String> tableNameOverrides = new HashMap<>();
        tableNameOverrides.put(null, "MyNewTableName");
        assertEncryptionContextUnchangedFromMap(EncryptionContext.builder().tableName("example").build(),
                tableNameOverrides);
    }

    @Test
    public void testNullCasesCreateEncryptionContextTableNameOverrideFromMap_nullNewTableName() {
        Map<String, String> tableNameOverrides = new HashMap<>();
        tableNameOverrides.put("MyOriginalTableName", null);
        assertEncryptionContextUnchangedFromMap(EncryptionContext.builder().tableName("MyOriginalTableName").build(),
                tableNameOverrides);
    }


    @Test
    public void testNullCasesCreateEncryptionContextTableNameOverrideFromMap_nullMap() {
        assertEncryptionContextUnchangedFromMap(EncryptionContext.builder().tableName("MyOriginalTableName").build(),
                null);
    }


    private void assertEncryptionContextUnchanged(EncryptionContext encryptionContext, String originalTableName, String newTableName) {
        Function<EncryptionContext, EncryptionContext> encryptionContextTableNameOverride = overrideEncryptionContextTableName(originalTableName, newTableName);
        EncryptionContext newEncryptionContext = encryptionContextTableNameOverride.apply(encryptionContext);
        assertEquals(encryptionContext, newEncryptionContext);
    }


    private void assertEncryptionContextUnchangedFromMap(EncryptionContext encryptionContext, Map<String, String> overrideMap) {
        Function<EncryptionContext, EncryptionContext> encryptionContextTableNameOverrideFromMap = overrideEncryptionContextTableNameUsingMap(overrideMap);
        EncryptionContext newEncryptionContext = encryptionContextTableNameOverrideFromMap.apply(encryptionContext);
        assertEquals(encryptionContext, newEncryptionContext);
    }
}
