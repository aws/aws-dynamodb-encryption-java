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
package software.amazon.awssdk.enhanced.dynamodb.internal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.quicktheories.QuickTheory.qt;
import static org.quicktheories.generators.Generate.byteArrays;
import static org.quicktheories.generators.Generate.bytes;
import static org.quicktheories.generators.SourceDSL.integers;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.testng.annotations.Test;

/** Tests for the Base64 interface used by the DynamoDBEncryptionClient */
public class Base64Tests {

  @Test
  public void testBase64DecodeEquivalence() {
    qt().forAll(
            byteArrays(
                integers().between(0, 10000), bytes(Byte.MIN_VALUE, Byte.MAX_VALUE, (byte) 0)))
        .as((b) -> java.util.Base64.getMimeEncoder().encodeToString(b))
        .check(
            (s) -> {
              // Check for equality using the MimeEncoder, which inserts newlines
              // The encryptionClient's decoder is expected to ignore them
              byte[] sdk1Bytes = com.amazonaws.util.Base64.decode(s);
              byte[] encryptionClientBase64 = software.amazon.awssdk.enhanced.dynamodb.internal.Base64.decode(s);
              return Arrays.equals(sdk1Bytes, encryptionClientBase64);
            });
  }

  @Test
  public void testNullDecodeBehavior() {
    byte[] decoded = software.amazon.awssdk.enhanced.dynamodb.internal.Base64.decode(null);
    assertThat(decoded, equalTo(null));
  }

  @Test
  public void testNullDecodeBehaviorSdk1() {
    byte[] decoded = com.amazonaws.util.Base64.decode((String) null);
    assertThat(decoded, equalTo(null));

    byte[] decoded2 = com.amazonaws.util.Base64.decode((byte[]) null);
    assertThat(decoded2, equalTo(null));
  }

  @Test
  public void testBase64PaddingBehavior() {
    String testInput = "another one bites the dust";
    String expectedEncoding = "YW5vdGhlciBvbmUgYml0ZXMgdGhlIGR1c3Q=";
    assertThat(
        software.amazon.awssdk.enhanced.dynamodb.internal.Base64.encodeToString(testInput.getBytes(StandardCharsets.UTF_8)),
        equalTo(expectedEncoding));

    String encodingWithoutPadding = "YW5vdGhlciBvbmUgYml0ZXMgdGhlIGR1c3Q";
    assertThat(software.amazon.awssdk.enhanced.dynamodb.internal.Base64.decode(encodingWithoutPadding), equalTo(testInput.getBytes()));
  }

  @Test(expectedExceptions = IllegalArgumentException.class)
  public void testBase64PaddingBehaviorSdk1() {
    String testInput = "another one bites the dust";
    String encodingWithoutPadding = "YW5vdGhlciBvbmUgYml0ZXMgdGhlIGR1c3Q";
    com.amazonaws.util.Base64.decode(encodingWithoutPadding);
  }

  @Test
  public void rfc4648TestVectors() {
    assertThat(software.amazon.awssdk.enhanced.dynamodb.internal.Base64.encodeToString("".getBytes(StandardCharsets.UTF_8)), equalTo(""));
    assertThat(software.amazon.awssdk.enhanced.dynamodb.internal.Base64.encodeToString("f".getBytes(StandardCharsets.UTF_8)), equalTo("Zg=="));
    assertThat(software.amazon.awssdk.enhanced.dynamodb.internal.Base64.encodeToString("fo".getBytes(StandardCharsets.UTF_8)), equalTo("Zm8="));
    assertThat(software.amazon.awssdk.enhanced.dynamodb.internal.Base64.encodeToString("foo".getBytes(StandardCharsets.UTF_8)), equalTo("Zm9v"));
    assertThat(software.amazon.awssdk.enhanced.dynamodb.internal.Base64.encodeToString("foob".getBytes(StandardCharsets.UTF_8)), equalTo("Zm9vYg=="));
    assertThat(
        software.amazon.awssdk.enhanced.dynamodb.internal.Base64.encodeToString("fooba".getBytes(StandardCharsets.UTF_8)), equalTo("Zm9vYmE="));
    assertThat(
        Base64.encodeToString("foobar".getBytes(StandardCharsets.UTF_8)), equalTo("Zm9vYmFy"));
  }
}
