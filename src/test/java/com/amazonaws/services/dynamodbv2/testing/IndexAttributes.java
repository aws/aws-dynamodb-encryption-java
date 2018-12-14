package com.amazonaws.services.dynamodbv2.testing;

import com.amazonaws.services.dynamodbv2.model.GlobalSecondaryIndex;
import com.amazonaws.services.dynamodbv2.model.GlobalSecondaryIndexDescription;
import com.amazonaws.services.dynamodbv2.model.KeySchemaElement;
import com.amazonaws.services.dynamodbv2.model.LocalSecondaryIndex;
import com.amazonaws.services.dynamodbv2.model.LocalSecondaryIndexDescription;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class IndexAttributes implements Comparable {
    private String indexName;
    private List<KeySchemaElement> keySchema;

    public IndexAttributes(String indexName, List<KeySchemaElement> keySchema) {
        this.indexName = indexName;
        this.keySchema = new ArrayList<>(keySchema);
    }

    public static IndexAttributes fromLsi(LocalSecondaryIndex lsi) {
        return new IndexAttributes(lsi.getIndexName(), lsi.getKeySchema());
    }

    public static IndexAttributes fromLsiDescription(LocalSecondaryIndexDescription lsi) {
        return new IndexAttributes(lsi.getIndexName(), lsi.getKeySchema());
    }

    public static IndexAttributes fromGsi(GlobalSecondaryIndex gsi) {
        return new IndexAttributes(gsi.getIndexName(), gsi.getKeySchema());
    }

    public static IndexAttributes fromGsiDescription(GlobalSecondaryIndexDescription gsi) {
        return new IndexAttributes(gsi.getIndexName(), gsi.getKeySchema());
    }

    public String getIndexName() {
        return indexName;
    }

    public void setIndexName(String indexName) {
        this.indexName = indexName;
    }

    public List<KeySchemaElement> getKeySchema() {
        return keySchema;
    }

    public void setKeySchema(List<KeySchemaElement> keySchema) {
        this.keySchema = keySchema;
    }

    @Override
    public int compareTo(Object o) {
        if (o instanceof IndexAttributes) {
            IndexAttributes o2 = (IndexAttributes) o;
            Comparator<String> c = Comparator.comparing(String::toString);
            int cmp = c.compare(this.getIndexName(), o2.getIndexName());
            if (cmp != 0) {
                return cmp;
            } else {
                return c.compare(this.getKeySchema().toString(), o2.getKeySchema().toString());
            }

        }
        throw new RuntimeException("Comparable only implemented for comparison against IndexAttributes");
    }
}
