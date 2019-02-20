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

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class AttrMatcher extends BaseMatcher<Map<String, AttributeValue>> {
    private final Map<String, AttributeValue> expected;
    private final boolean invert;

    public static AttrMatcher invert(Map<String, AttributeValue> expected) {
        return new AttrMatcher(expected, true);
    }

    public static AttrMatcher match(Map<String, AttributeValue> expected) {
        return new AttrMatcher(expected, false);
    }

    public AttrMatcher(Map<String, AttributeValue> expected, boolean invert) {
        this.expected = expected;
        this.invert = invert;
    }

    @Override
    public boolean matches(Object item) {
        @SuppressWarnings("unchecked")
        Map<String, AttributeValue> actual = (Map<String, AttributeValue>) item;
        if (!expected.keySet().equals(actual.keySet())) {
            return invert;
        }
        for (String key : expected.keySet()) {
            AttributeValue e = expected.get(key);
            AttributeValue a = actual.get(key);
            if (!attrEquals(a, e)) {
                return invert;
            }
        }
        return !invert;
    }

    public static boolean attrEquals(AttributeValue e, AttributeValue a) {
        if (!isEqual(e.getB(), a.getB()) ||
                !isEqual(e.getBOOL(), a.getBOOL()) ||
                !isSetEqual(e.getBS(), a.getBS()) ||
                !isEqual(e.getN(), a.getN()) ||
                !isSetEqual(e.getNS(), a.getNS()) ||
                !isEqual(e.getNULL(), a.getNULL()) ||
                !isEqual(e.getS(), a.getS()) ||
                !isSetEqual(e.getSS(), a.getSS())) {
            return false;
        }
        // Recursive types need special handling
        if (e.getM() == null ^ a.getM() == null) {
            return false;
        } else if (e.getM() != null) {
            if (!e.getM().keySet().equals(a.getM().keySet())) {
                return false;
            }
            for (final String key : e.getM().keySet()) {
                if (!attrEquals(e.getM().get(key), a.getM().get(key))) {
                    return false;
                }
            }
        }
        if (e.getL() == null ^ a.getL() == null) {
            return false;
        } else if (e.getL() != null) {
            if (e.getL().size() != a.getL().size()) {
                return false;
            }
            for (int x = 0; x < e.getL().size(); x++) {
                if (!attrEquals(e.getL().get(x), a.getL().get(x))) {
                    return false;
                }
            }
        }
        return true;
    }

    @Override
    public void describeTo(Description description) {
    }

    private static boolean isEqual(Object o1, Object o2) {
        if (o1 == null ^ o2 == null) {
            return false;
        }
        if (o1 == o2)
            return true;
        return o1.equals(o2);
    }

    private static <T> boolean isSetEqual(Collection<T> c1, Collection<T> c2) {
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
