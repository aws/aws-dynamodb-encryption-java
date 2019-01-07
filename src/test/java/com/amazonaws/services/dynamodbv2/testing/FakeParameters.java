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

import com.amazonaws.services.dynamodbv2.datamodeling.AttributeTransformer;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBMapperConfig;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Collections;
import java.util.Map;

public class FakeParameters<T> {
    public static <T> AttributeTransformer.Parameters<T> getInstance(Class<T> clazz,
                                                                     Map<String, AttributeValue> attribs, DynamoDBMapperConfig config, String tableName,
                                                                     String hashKeyName, String rangeKeyName) {
        return getInstance(clazz, attribs, config, tableName, hashKeyName, rangeKeyName, false);
    }

    public static <T> AttributeTransformer.Parameters<T> getInstance(Class<T> clazz,
                                                                     Map<String, AttributeValue> attribs, DynamoDBMapperConfig config, String tableName,
                                                                     String hashKeyName, String rangeKeyName, boolean isPartialUpdate) {

        // We use this relatively insane proxy setup so that modifications to the Parameters
        // interface doesn't break our tests (unless it actually impacts our code).
        FakeParameters<T> fakeParams = new FakeParameters<T>(clazz, attribs, config, tableName,
                hashKeyName, rangeKeyName, isPartialUpdate);
        @SuppressWarnings("unchecked")
        AttributeTransformer.Parameters<T> proxyObject = (AttributeTransformer.Parameters<T>) Proxy
                .newProxyInstance(AttributeTransformer.class.getClassLoader(),
                        new Class[]{AttributeTransformer.Parameters.class},
                        new ParametersInvocationHandler<T>(fakeParams));
        return proxyObject;
    }

    private static class ParametersInvocationHandler<T> implements InvocationHandler {
        private final FakeParameters<T> params;

        public ParametersInvocationHandler(FakeParameters<T> params) {
            this.params = params;
        }

        @Override
        public Object invoke(Object obj, Method method, Object[] args) throws Throwable {
            if (args != null && args.length > 0) {
                throw new UnsupportedOperationException();
            }
            Method innerMethod = params.getClass().getMethod(method.getName());
            return innerMethod.invoke(params);
        }

    }

    private final Map<String, AttributeValue> attrs;
    private final Class<T> clazz;
    private final DynamoDBMapperConfig config;
    private final String tableName;
    private final String hashKeyName;
    private final String rangeKeyName;
    private final boolean isPartialUpdate;

    private FakeParameters(Class<T> clazz, Map<String, AttributeValue> attribs,
                           DynamoDBMapperConfig config, String tableName, String hashKeyName, String rangeKeyName,
                           boolean isPartialUpdate) {
        super();
        this.clazz = clazz;
        this.attrs = Collections.unmodifiableMap(attribs);
        this.config = config;
        this.tableName = tableName;
        this.hashKeyName = hashKeyName;
        this.rangeKeyName = rangeKeyName;
        this.isPartialUpdate = isPartialUpdate;
    }

    public Map<String, AttributeValue> getAttributeValues() {
        return attrs;
    }

    public Class<T> getModelClass() {
        return clazz;
    }

    public DynamoDBMapperConfig getMapperConfig() {
        return config;
    }

    public String getTableName() {
        return tableName;
    }

    public String getHashKeyName() {
        return hashKeyName;
    }

    public String getRangeKeyName() {
        return rangeKeyName;
    }

    public boolean isPartialUpdate() {
        return isPartialUpdate;
    }
}
