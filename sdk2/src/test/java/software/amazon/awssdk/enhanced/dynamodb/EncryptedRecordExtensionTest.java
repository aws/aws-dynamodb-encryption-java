/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package software.amazon.awssdk.enhanced.dynamodb;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.comparesEqualTo;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static software.amazon.awssdk.enhanced.dynamodb.internal.tags.EncryptionExtensionTags.encrypted;
import static software.amazon.awssdk.enhanced.dynamodb.internal.tags.EncryptionExtensionTags.signed;
import static software.amazon.awssdk.enhanced.dynamodb.mapper.StaticAttributeTags.primaryPartitionKey;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import software.amazon.awssdk.enhanced.dynamodb.encryption.providers.EncryptionMaterialsProvider;
import software.amazon.awssdk.enhanced.dynamodb.encryption.providers.SymmetricStaticProvider;
import software.amazon.awssdk.enhanced.dynamodb.extensions.ReadModification;
import software.amazon.awssdk.enhanced.dynamodb.extensions.WriteModification;
import software.amazon.awssdk.enhanced.dynamodb.internal.Utils;
import software.amazon.awssdk.enhanced.dynamodb.internal.extensions.DefaultDynamoDbExtensionContext;
import software.amazon.awssdk.enhanced.dynamodb.internal.operations.DefaultOperationContext;
import software.amazon.awssdk.enhanced.dynamodb.mapper.StaticTableSchema;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

public class EncryptedRecordExtensionTest {
    private static final String RECORD_ID = "id123";

    private static final String TABLE_NAME = "table-name";
    private static final OperationContext PRIMARY_CONTEXT =
            DefaultOperationContext.create(TABLE_NAME, TableMetadata.primaryIndexName());

    private EncryptedRecordExtension extension;

    private static SecretKey encryptionKey;
    private static SecretKey macKey;

    @BeforeClass
    public static void setUpClass() throws Exception {
        KeyGenerator aesGen = KeyGenerator.getInstance("AES");
        aesGen.init(128, Utils.getRng());
        encryptionKey = aesGen.generateKey();

        KeyGenerator macGen = KeyGenerator.getInstance("HmacSHA256");
        macGen.init(256, Utils.getRng());
        macKey = macGen.generateKey();
    }

    @BeforeMethod(alwaysRun = true)
    public void setUp() {
        EncryptionMaterialsProvider materials = new SymmetricStaticProvider(encryptionKey, macKey, Collections.<String, String>emptyMap());
        extension = EncryptedRecordExtension.builder()
                .encryptionMaterialsProvider(materials)
                .build();
    }


    private static final StaticTableSchema<CryptoItem> ITEM_MAPPER =
            StaticTableSchema.builder(CryptoItem.class)
                    .newItemSupplier(CryptoItem::new)
                    .addAttribute(String.class, a -> a.name("id")
                            .getter(CryptoItem::getId)
                            .setter(CryptoItem::setId)
                            .addTag(primaryPartitionKey()))
                    .addAttribute(String.class, a -> a.name("encryptedString")
                            .getter(CryptoItem::getEncryptedString)
                            .setter(CryptoItem::setEncryptedString)
                            .addTag(encrypted()))
                    .addAttribute(String.class, a -> a.name("signedString")
                            .getter(CryptoItem::getSignedString)
                            .setter(CryptoItem::setSignedString)
                            .addTag(signed()))
                    .addAttribute(String.class, a -> a.name("encryptedAndSignedString")
                            .getter(CryptoItem::getEncryptedAndSignedString)
                            .setter(CryptoItem::setEncryptedAndSignedString)
                            .tags(encrypted(), signed()))
                    .addAttribute(String.class, a -> a.name("ignoredString")
                            .getter(CryptoItem::getIgnoredString)
                            .setter(CryptoItem::setIgnoredString))
                    .build();

    private static final StaticTableSchema<SimpleItem> SIMPLE_ITEM_MAPPER =
            StaticTableSchema.builder(SimpleItem.class)
                    .newItemSupplier(SimpleItem::new)
                    .addAttribute(String.class, a -> a.name("id")
                            .getter(SimpleItem::getId)
                            .setter(SimpleItem::setId)
                            .addTag(primaryPartitionKey()))
                    .addAttribute(Long.class, a -> a.name("numberAttribute")
                            .getter(SimpleItem::getNumberAttribute)
                            .setter(SimpleItem::setNumberAttribute))
                    .build();


    @Test
    public void beforeWrite_putItemOperation_hasEncryption_createsItemTransform() {
        CryptoItem cryptoItem = new CryptoItem();
        cryptoItem.setId(RECORD_ID);
        cryptoItem.setEncryptedString("Encrypted String");
        cryptoItem.setSignedString("Signed String");
        cryptoItem.setIgnoredString("Ignored String");
        cryptoItem.setEncryptedAndSignedString("Encrypted and Signed String");

        Map<String, AttributeValue> items = ITEM_MAPPER.itemToMap(cryptoItem, true);
        assertThat(items.size(), equalTo(5));
        assertThat(items, allOf(
                hasKey("id"),
                hasKey("encryptedString"),
                hasKey("signedString"),
                hasKey("ignoredString"),
                hasKey("encryptedAndSignedString")));

        WriteModification result =
                extension.beforeWrite(DefaultDynamoDbExtensionContext.builder()
                        .items(items)
                        .tableMetadata(ITEM_MAPPER.tableMetadata())
                        .operationContext(PRIMARY_CONTEXT).build());

        Map<String, AttributeValue> transformedItem = result.transformedItem();

        assertThat(transformedItem, allOf(
                notNullValue(),
                hasKey("id"),
                hasKey("encryptedString"),
                hasKey("signedString"),
                hasKey("ignoredString"),
                hasKey("encryptedAndSignedString"),
                hasKey("*amzn-ddb-map-desc*"),
                hasKey("*amzn-ddb-map-sig*")));
        assertThat(transformedItem.size(), equalTo(7));
        assertThat(transformedItem.get("encryptedString").b(), notNullValue());
        assertThat(transformedItem.get("encryptedAndSignedString").b(), notNullValue());
        assertThat(transformedItem.get("signedString").s(), notNullValue());
        assertThat(transformedItem.get("ignoredString").s(), notNullValue());
    }

    @Test
    public void beforeWrite_putItemOperation_noEncryption_createsItemTransform() {
        SimpleItem item = new SimpleItem();
        item.setId(RECORD_ID);
        item.setNumberAttribute(256L);

        Map<String, AttributeValue> items = SIMPLE_ITEM_MAPPER.itemToMap(item, true);
        assertThat(items.size(), equalTo(2));
        assertThat(items, allOf(
                hasKey("id"),
                hasKey("numberAttribute")));

        WriteModification result =
                extension.beforeWrite(DefaultDynamoDbExtensionContext.builder()
                        .items(items)
                        .tableMetadata(SIMPLE_ITEM_MAPPER.tableMetadata())
                        .operationContext(PRIMARY_CONTEXT).build());

        Map<String, AttributeValue> transformedItem = result.transformedItem();
        System.out.println(transformedItem);

        assertThat(transformedItem, allOf(
                notNullValue(),
                hasKey("id"),
                hasKey("numberAttribute"),
                not(hasKey("*amzn-ddb-map-desc*")),
                not(hasKey("*amzn-ddb-map-sig*"))));
        assertThat(transformedItem.size(), equalTo(2));
        assertThat(transformedItem.get("id").s(), comparesEqualTo(RECORD_ID));
    }

    @Test
    public void roundtrip() {
        CryptoItem cryptoItem = new CryptoItem();
        cryptoItem.setId(RECORD_ID);
        cryptoItem.setEncryptedString("Encrypted String");
        cryptoItem.setSignedString("Signed String");
        cryptoItem.setIgnoredString("Ignored String");
        cryptoItem.setEncryptedAndSignedString("Encrypted and Signed String");

        Map<String, AttributeValue> items = ITEM_MAPPER.itemToMap(cryptoItem, true);

        WriteModification result =
                extension.beforeWrite(DefaultDynamoDbExtensionContext.builder()
                        .items(items)
                        .tableMetadata(ITEM_MAPPER.tableMetadata())
                        .operationContext(PRIMARY_CONTEXT).build());

        System.out.println(result.transformedItem());

        ReadModification readModification = extension.afterRead(DefaultDynamoDbExtensionContext.builder()
                .items(result.transformedItem())
                .tableMetadata(ITEM_MAPPER.tableMetadata())
                .operationContext(PRIMARY_CONTEXT)
                .build());

        System.out.println(readModification.transformedItem());
        CryptoItem roundtripItem = ITEM_MAPPER.mapToItem(readModification.transformedItem());

        assertThat(roundtripItem, equalTo(cryptoItem));
    }


    @Test
    public void signature_change_ignored() {
        CryptoItem cryptoItem = new CryptoItem();
        cryptoItem.setId(RECORD_ID);
        cryptoItem.setEncryptedString("Encrypted String");
        cryptoItem.setSignedString("Signed String");
        cryptoItem.setIgnoredString("Ignored String");

        Map<String, AttributeValue> items = ITEM_MAPPER.itemToMap(cryptoItem, true);

        WriteModification result =
                extension.beforeWrite(DefaultDynamoDbExtensionContext.builder()
                        .items(items)
                        .tableMetadata(ITEM_MAPPER.tableMetadata())
                        .operationContext(PRIMARY_CONTEXT).build());

        Map<String, AttributeValue> transformedItem = result.transformedItem();
        transformedItem.put("ignoredString", AttributeValue.builder()
                .s("This won't impact the signature")
                .build());
        cryptoItem.setIgnoredString("This won't impact the signature");

        ReadModification readModification = extension.afterRead(DefaultDynamoDbExtensionContext.builder()
                .items(transformedItem)
                .tableMetadata(ITEM_MAPPER.tableMetadata())
                .operationContext(PRIMARY_CONTEXT)
                .build());

        CryptoItem roundtripItem = ITEM_MAPPER.mapToItem(readModification.transformedItem());

        assertThat(roundtripItem, equalTo(cryptoItem));
    }

    @Test(expectedExceptions = EncryptionException.class, expectedExceptionsMessageRegExp = ".*Bad signature")
    public void signature_change_signed() {
        CryptoItem cryptoItem = new CryptoItem();
        cryptoItem.setId(RECORD_ID);
        cryptoItem.setEncryptedString("Encrypted String");
        cryptoItem.setSignedString("Signed String");
        cryptoItem.setIgnoredString("Ignored String");

        Map<String, AttributeValue> items = ITEM_MAPPER.itemToMap(cryptoItem, true);

        WriteModification result =
                extension.beforeWrite(DefaultDynamoDbExtensionContext.builder()
                        .items(items)
                        .tableMetadata(ITEM_MAPPER.tableMetadata())
                        .operationContext(PRIMARY_CONTEXT).build());

        Map<String, AttributeValue> transformedItem = result.transformedItem();
        cryptoItem.setSignedString("This will break signature");
        transformedItem.put("signedString", AttributeValue.builder()
                .s(cryptoItem.signedString)
                .build());


        extension.afterRead(DefaultDynamoDbExtensionContext.builder()
                .items(transformedItem)
                .tableMetadata(ITEM_MAPPER.tableMetadata())
                .operationContext(PRIMARY_CONTEXT)
                .build());
    }

    @Test(expectedExceptions = EncryptionException.class, expectedExceptionsMessageRegExp = ".*Bad signature")
    public void signature_change_encrypted_and_signed() {
        CryptoItem cryptoItem = new CryptoItem();
        cryptoItem.setId(RECORD_ID);
        cryptoItem.setEncryptedString("Encrypted String");
        cryptoItem.setSignedString("Signed String");
        cryptoItem.setIgnoredString("Ignored String");

        Map<String, AttributeValue> items = ITEM_MAPPER.itemToMap(cryptoItem, true);

        WriteModification result =
                extension.beforeWrite(DefaultDynamoDbExtensionContext.builder()
                        .items(items)
                        .tableMetadata(ITEM_MAPPER.tableMetadata())
                        .operationContext(PRIMARY_CONTEXT).build());

        Map<String, AttributeValue> transformedItem = result.transformedItem();
        cryptoItem.setEncryptedAndSignedString("This will break signature");
        transformedItem.put("encryptedAndSignedString", AttributeValue.builder()
                .s(cryptoItem.encryptedAndSignedString)
                .build());

        extension.afterRead(DefaultDynamoDbExtensionContext.builder()
                .items(transformedItem)
                .tableMetadata(ITEM_MAPPER.tableMetadata())
                .operationContext(PRIMARY_CONTEXT)
                .build());
    }

    private static class CryptoItem {

        private String id;
        private String encryptedString;

        private String encryptedAndSignedString;
        private String signedString;

        public String getEncryptedAndSignedString() {
            return encryptedAndSignedString;
        }

        public void setEncryptedAndSignedString(String encryptedAndSignedString) {
            this.encryptedAndSignedString = encryptedAndSignedString;
        }

        public String getIgnoredString() {
            return ignoredString;
        }

        public void setIgnoredString(String ignoredString) {
            this.ignoredString = ignoredString;
        }

        private String ignoredString;

        public CryptoItem() {
        }

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public String getEncryptedString() {
            return encryptedString;
        }

        public void setEncryptedString(String encryptedString) {
            this.encryptedString = encryptedString;
        }

        public String getSignedString() {
            return signedString;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            CryptoItem that = (CryptoItem) o;
            return id.equals(that.id) && Objects.equals(encryptedString, that.encryptedString) && Objects.equals(encryptedAndSignedString, that.encryptedAndSignedString) && Objects.equals(signedString, that.signedString) && Objects.equals(ignoredString, that.ignoredString);
        }

        @Override
        public int hashCode() {
            return Objects.hash(id, encryptedString, encryptedAndSignedString, signedString, ignoredString);
        }

        @Override
        public String toString() {
            return new ToStringBuilder(this)
                    .append("id", id)
                    .append("encryptedString", encryptedString)
                    .append("signedString", signedString)
                    .append("ignoredString", ignoredString)
                    .append("encryptedAndSignedString", encryptedAndSignedString)
                    .toString();
        }

        public void setSignedString(String signedString) {
            this.signedString = signedString;
        }

    }


    private static class SimpleItem {

        private String id;
        private Long numberAttribute;

        public SimpleItem() {
        }

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public Long getNumberAttribute() {
            return numberAttribute;
        }

        public void setNumberAttribute(Long numberAttribute) {
            this.numberAttribute = numberAttribute;
        }


        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            if (!super.equals(o)) return false;
            SimpleItem item = (SimpleItem) o;
            return Objects.equals(id, item.id) &&
                    Objects.equals(numberAttribute, item.numberAttribute);
        }

        @Override
        public int hashCode() {
            return Objects.hash(super.hashCode(), id, numberAttribute);
        }
    }
}
