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
package com.amazonaws.services.dynamodbv2.testing.types;

import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DoNotEncrypt;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.DoNotTouch;

import java.util.Set;

public class Mixed extends BaseClass {
    @Override
    @DoNotEncrypt
    public String getStringValue() {
        return super.getStringValue();
    }

    @Override
    @DoNotEncrypt
    public double getDoubleValue() {
        return super.getDoubleValue();
    }

    @Override
    @DoNotEncrypt
    public Set<Double> getDoubleSet() {
        return super.getDoubleSet();
    }

    @Override
    @DoNotTouch
    public int getIntValue() {
        return super.getIntValue();
    }
}
