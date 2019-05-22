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
package software.amazon.cryptools.dynamodbencryptionclientsdk2.testing;

import java.util.List;
import java.util.Map;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

/**
 * Static helper methods to construct standard AttributeValues in a more compact way than specifying the full builder
 * chain.
 */
public final class AttributeValueBuilder {
    private AttributeValueBuilder() {
        // Static helper class
    }

    public static AttributeValue ofS(String value) {
        return AttributeValue.builder().s(value).build();
    }

    public static AttributeValue ofN(String value) {
        return AttributeValue.builder().n(value).build();
    }

    public static AttributeValue ofB(byte [] value) {
        return AttributeValue.builder().b(SdkBytes.fromByteArray(value)).build();
    }

    public static AttributeValue ofBool(Boolean value) {
        return AttributeValue.builder().bool(value).build();
    }

    public static AttributeValue ofNull() {
        return AttributeValue.builder().nul(true).build();
    }

    public static AttributeValue ofL(List<AttributeValue> values) {
        return AttributeValue.builder().l(values).build();
    }

    public static AttributeValue ofL(AttributeValue ...values) {
        return AttributeValue.builder().l(values).build();
    }

    public static AttributeValue ofM(Map<String, AttributeValue> valueMap) {
        return AttributeValue.builder().m(valueMap).build();
    }

    public static AttributeValue ofSS(String ...values) {
        return AttributeValue.builder().ss(values).build();
    }
}
