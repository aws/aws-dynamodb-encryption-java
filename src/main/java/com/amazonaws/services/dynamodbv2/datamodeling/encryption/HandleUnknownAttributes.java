/*
 * Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
package com.amazonaws.services.dynamodbv2.datamodeling.encryption;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marker annotation that indicates that attributes found during unmarshalling
 * that are in the DynamoDB item but not modeled in the mapper model class
 * should be included in for decryption/signature verification. The default
 * behavior (without this annotation) is to ignore them, which can lead to 
 * signature verification failures when attributes are removed from model classes.
 * 
 * If this annotation is added to a class with @DoNotEncrypt, then the unknown
 * attributes will only be included in the signature calculation, and if it's
 * added to a class with default encryption behavior, the unknown attributes
 * will be signed and decrypted.
 * 
 * @author Dan Cavallaro 
 */
@Target(value = {ElementType.TYPE})
@Retention(value = RetentionPolicy.RUNTIME)
public @interface HandleUnknownAttributes {}
