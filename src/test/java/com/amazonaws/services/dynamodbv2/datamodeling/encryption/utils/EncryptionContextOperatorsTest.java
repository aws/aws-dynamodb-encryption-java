package com.amazonaws.services.dynamodbv2.datamodeling.encryption.utils;

import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionContext;
import org.testng.annotations.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import static com.amazonaws.services.dynamodbv2.datamodeling.encryption.utils.EncryptionContextOperators.overrideEncryptionContextTableName;
import static com.amazonaws.services.dynamodbv2.datamodeling.encryption.utils.EncryptionContextOperators.overrideEncryptionContextTableNameUsingMap;
import static org.testng.AssertJUnit.assertEquals;

public class EncryptionContextOperatorsTest {

    @Test
    public void testCreateEncryptionContextTableNameOverride_expectedOverride() {
        Function<EncryptionContext, EncryptionContext> myNewTableName = overrideEncryptionContextTableName("OriginalTableName", "MyNewTableName");

        EncryptionContext context = new EncryptionContext.Builder().withTableName("OriginalTableName").build();

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
        assertEncryptionContextUnchanged(new EncryptionContext.Builder().withTableName("example").build(),
                null,
                "MyNewTableName");
    }

    @Test
    public void testCreateEncryptionContextTableNameOverride_differentOriginalTableName() {
        assertEncryptionContextUnchanged(new EncryptionContext.Builder().withTableName("example").build(),
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

        EncryptionContext context = new EncryptionContext.Builder().withTableName("OriginalTableName").build();

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

        EncryptionContext context = new EncryptionContext.Builder().withTableName("OriginalTableName1").build();

        EncryptionContext newContext = overrideOperator.apply(context);

        assertEquals("OriginalTableName1", context.getTableName());
        assertEquals("MyNewTableName1", newContext.getTableName());

        EncryptionContext context2 = new EncryptionContext.Builder().withTableName("OriginalTableName2").build();

        EncryptionContext newContext2 = overrideOperator.apply(context2);

        assertEquals("OriginalTableName2", context2.getTableName());
        assertEquals("MyNewTableName2", newContext2.getTableName());

    }


    @Test
    public void testNullCasesCreateEncryptionContextTableNameOverrideFromMap_nullEncryptionContextTableName() {
        Map<String, String> tableNameOverrides = new HashMap<>();
        tableNameOverrides.put("DifferentTableName", "MyNewTableName");
        assertEncryptionContextUnchangedFromMap(new EncryptionContext.Builder().build(),
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
        assertEncryptionContextUnchangedFromMap(new EncryptionContext.Builder().withTableName("example").build(),
                tableNameOverrides);
    }

    @Test
    public void testNullCasesCreateEncryptionContextTableNameOverrideFromMap_nullNewTableName() {
        Map<String, String> tableNameOverrides = new HashMap<>();
        tableNameOverrides.put("MyOriginalTableName", null);
        assertEncryptionContextUnchangedFromMap(new EncryptionContext.Builder().withTableName("MyOriginalTableName").build(),
                tableNameOverrides);
    }


    @Test
    public void testNullCasesCreateEncryptionContextTableNameOverrideFromMap_nullMap() {
        assertEncryptionContextUnchangedFromMap(new EncryptionContext.Builder().withTableName("MyOriginalTableName").build(),
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
