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
package software.amazon.cryptools.dynamodbencryptionclientsdk2;

/**
 * When configuring the {@link DynamoDbEncryptionClient} you may specify a default behavior for how attributes should
 * be treated when encrypting and decrypting, and also you may include overrides to change the behavior for specific
 * attributes. The following enumeration are the different valid behaviors for how a single attribute should be treated.
 */
public enum EncryptionAction {
    /**
     * DO_NOTHING : This instructs the encryption client to completely ignore the attribute. The attribute will not be
     *              encrypted and it will not be included in the signature calculation of the record.
     */
    DO_NOTHING,

    /**
     * SIGN_ONLY : This instructs the encryption client to include the attribute in the signature calculation of the
     *             record, but not to encrypt its value.
     */
    SIGN_ONLY,

    /**
     * ENCRYPT_AND_SIGN : This instructs the encryption client to include the attribute in the signature calculation of
     *                    the record and to encrypt its value.
     */
    ENCRYPT_AND_SIGN
}
