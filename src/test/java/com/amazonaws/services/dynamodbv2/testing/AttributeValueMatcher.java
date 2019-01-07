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
package com.amazonaws.services.dynamodbv2.testing;

import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;

import java.math.BigDecimal;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

public class AttributeValueMatcher extends BaseMatcher<AttributeValue> {
    private final AttributeValue expected;
    private final boolean invert;

    public static AttributeValueMatcher invert(AttributeValue expected) {
        return new AttributeValueMatcher(expected, true);
    }

    public static AttributeValueMatcher match(AttributeValue expected) {
        return new AttributeValueMatcher(expected, false);
    }

    public AttributeValueMatcher(AttributeValue expected, boolean invert) {
        this.expected = expected;
        this.invert = invert;
    }

    @Override
    public boolean matches(Object item) {
        AttributeValue other = (AttributeValue) item;
        return invert ^ attrEquals(expected, other);
    }

    @Override
    public void describeTo(Description description) {
    }

    public static boolean attrEquals(AttributeValue e, AttributeValue a) {
        if (!isEqual(e.getB(), a.getB()) ||
                !isNumberEqual(e.getN(), a.getN()) ||
                !isEqual(e.getS(), a.getS()) ||
                !isEqual(e.getBS(), a.getBS()) ||
                !isNumberEqual(e.getNS(), a.getNS()) ||
                !isEqual(e.getSS(), a.getSS())) {
            return false;
        }
        return true;
    }

    private static boolean isNumberEqual(String o1, String o2) {
        if (o1 == null ^ o2 == null) {
            return false;
        }
        if (o1 == o2)
            return true;
        BigDecimal d1 = new BigDecimal(o1);
        BigDecimal d2 = new BigDecimal(o2);
        return d1.equals(d2);
    }

    private static boolean isEqual(Object o1, Object o2) {
        if (o1 == null ^ o2 == null) {
            return false;
        }
        if (o1 == o2)
            return true;
        return o1.equals(o2);
    }

    private static boolean isNumberEqual(Collection<String> c1, Collection<String> c2) {
        if (c1 == null ^ c2 == null) {
            return false;
        }
        if (c1 != null) {
            Set<BigDecimal> s1 = new HashSet<BigDecimal>();
            Set<BigDecimal> s2 = new HashSet<BigDecimal>();
            for (String s : c1) {
                s1.add(new BigDecimal(s));
            }
            for (String s : c2) {
                s2.add(new BigDecimal(s));
            }
            if (!s1.equals(s2)) {
                return false;
            }
        }
        return true;
    }

    private static <T> boolean isEqual(Collection<T> c1, Collection<T> c2) {
        if (c1 == null ^ c2 == null) {
            return false;
        }
        if (c1 != null) {
            Set<T> s1 = new HashSet<T>(c1);
            Set<T> s2 = new HashSet<T>(c2);
            if (!s1.equals(s2)) {
                return false;
            }
        }
        return true;
    }
}
