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

import java.util.Map;

public class DdbRecordMatcher extends BaseMatcher<Map<String, AttributeValue>> {
    private final Map<String, AttributeValue> expected;
    private final boolean invert;

    public static DdbRecordMatcher invert(Map<String, AttributeValue> expected) {
        return new DdbRecordMatcher(expected, true);
    }

    public static DdbRecordMatcher match(Map<String, AttributeValue> expected) {
        return new DdbRecordMatcher(expected, false);
    }

    public DdbRecordMatcher(Map<String, AttributeValue> expected, boolean invert) {
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
            if (!AttributeValueMatcher.attrEquals(a, e)) {
                return invert;
            }
        }
        return !invert;
    }

    @Override
    public void describeTo(Description description) {
    }


}
