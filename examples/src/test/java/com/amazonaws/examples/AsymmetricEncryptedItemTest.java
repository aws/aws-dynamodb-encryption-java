// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.amazonaws.examples;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import org.testng.annotations.Test;

public class AsymmetricEncryptedItemTest {
  private static final String TABLE_NAME = "java-ddbec-test-table-asym-example";

  @Test
  public void testEncryptAndDecrypt() throws GeneralSecurityException {
    final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    final KeyPair wrappingKeys = keyGen.generateKeyPair();
    final KeyPair signingKeys = keyGen.generateKeyPair();

    AsymmetricEncryptedItem.encryptRecord(TABLE_NAME, wrappingKeys, signingKeys);
  }
}
