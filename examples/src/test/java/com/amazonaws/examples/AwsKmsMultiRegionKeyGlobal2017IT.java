// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.examples;

import org.testng.annotations.Test;

import java.security.GeneralSecurityException;

import static com.amazonaws.examples.TestUtils.US_EAST_1_MRK_KEY_ID;
import static com.amazonaws.examples.TestUtils.US_WEST_2_MRK_KEY_ID;

public class AwsKmsMultiRegionKeyGlobal2017IT {
  private static final String TABLE_NAME = "tonyknap-manual-mrk-global-2017";

  @Test
  public void testEncryptAndDecrypt() throws GeneralSecurityException {
    AwsKmsMultiRegionKeyGlobal2017.encryptAndDecrypt(TABLE_NAME, US_EAST_1_MRK_KEY_ID, US_WEST_2_MRK_KEY_ID);
  }
}
