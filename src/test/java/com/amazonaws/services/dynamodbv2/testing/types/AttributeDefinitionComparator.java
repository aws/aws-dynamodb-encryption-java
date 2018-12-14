package com.amazonaws.services.dynamodbv2.testing.types;

import com.amazonaws.services.dynamodbv2.model.AttributeDefinition;

import java.util.Comparator;

public class AttributeDefinitionComparator implements Comparator<AttributeDefinition> {

    @Override
    public int compare(AttributeDefinition o1, AttributeDefinition o2) {
        Comparator<String> c = Comparator.comparing(String::toString);
        int cmp = c.compare(o1.getAttributeName(), o2.getAttributeName());
        if (cmp != 0) {
            return cmp;
        } else {
            return c.compare(o1.getAttributeType(), o2.getAttributeType());
        }
    }
}
