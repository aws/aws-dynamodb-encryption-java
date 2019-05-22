/*
 * Copyright 2014-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
package software.amazon.cryptools.dynamodbencryptionclientsdk2.testing;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;

import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

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
        Map<String, AttributeValue> actual = (Map<String, AttributeValue>)item;
        if (!expected.keySet().equals(actual.keySet())) {
            return invert;
        }
        for (String key: expected.keySet()) {
            AttributeValue e = expected.get(key);
            AttributeValue a = actual.get(key);
            if (!attrEquals(a, e)) {
                return invert;
            }
        }
        return !invert;
    }

    public static boolean attrEquals(AttributeValue e, AttributeValue a) {
        if (!isEqual(e.b(), a.b()) ||
                !isEqual(e.bool(), a.bool()) ||
                !isSetEqual(e.bs(), a.bs()) ||
                !isEqual(e.n(), a.n()) ||
                !isSetEqual(e.ns(), a.ns()) ||
                !isEqual(e.nul(), a.nul()) ||
                !isEqual(e.s(), a.s()) ||
                !isSetEqual(e.ss(), a.ss())) {
            return false;
        }
        // Recursive types need special handling
        if (e.m() == null ^ a.m() == null) {
            return false;
        } else if (e.m() != null) {
            if (!e.m().keySet().equals(a.m().keySet())) {
                return false;
            }
            for (final String key : e.m().keySet()) {
                if (!attrEquals(e.m().get(key), a.m().get(key))) {
                    return false;
                }
            }
        }
        if (e.l() == null ^ a.l() == null) {
            return false;
        } else if (e.l() != null) {
            if (e.l().size() != a.l().size()) {
                return false;
            }
            for (int x = 0; x < e.l().size(); x++) {
                if (!attrEquals(e.l().get(x), a.l().get(x))) {
                    return false;
                }
            }
        }
        return true;
    }
    
    @Override
    public void describeTo(Description description) { }
    
    private static boolean isEqual(Object o1, Object o2) {
        if(o1 == null ^ o2 == null) {
            return false;
        }
        if (o1 == o2)
            return true;
        return o1.equals(o2);
    }
    
    private static <T> boolean isSetEqual(Collection<T> c1, Collection<T> c2) {
        if(c1 == null ^ c2 == null) {
            return false;
        }
        if (c1 != null) {
            Set<T> s1 = new HashSet<T>(c1);
            Set<T> s2 = new HashSet<T>(c2);
            if(!s1.equals(s2)) {
                return false;
            }
        }
        return true;
    }
}