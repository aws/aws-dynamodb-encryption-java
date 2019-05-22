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
package software.amazon.cryptools.dynamodbencryptionclientsdk2.encryption.exceptions;

/**
 * Generic exception thrown for any problem the DynamoDB encryption client has performing tasks
 */
public class DynamoDbEncryptionException extends RuntimeException {
    private static final long serialVersionUID = - 7565904179772520868L;

    /**
     * Standard constructor
     * @param cause exception cause
     */
    public DynamoDbEncryptionException(Throwable cause) {
        super(cause);
    }

    /**
     * Standard constructor
     * @param message exception message
     */
    public DynamoDbEncryptionException(String message) {
        super(message);
    }

    /**
     * Standard constructor
     * @param message exception message
     * @param cause exception cause
     */
    public DynamoDbEncryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
