// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.examples;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import org.testng.annotations.Test;

import java.security.GeneralSecurityException;

import static com.amazonaws.examples.TestUtils.US_WEST_2;
import static com.amazonaws.examples.TestUtils.US_WEST_2_KEY_ID;

public class AwsKmsEncryptedItemIT {
    private static final String TABLE_NAME = "java-ddbec-test-table-kms-item-example";

    @Test
    public void testEncryptAndDecrypt() throws GeneralSecurityException {
        final AWSKMS kms = AWSKMSClientBuilder.standard().withRegion(US_WEST_2).build();
        AwsKmsEncryptedItem.encryptRecord(TABLE_NAME, US_WEST_2_KEY_ID, kms);
    }
}
