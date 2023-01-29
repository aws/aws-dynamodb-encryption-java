/*
 * Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except
 * in compliance with the License. A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package software.amazon.awssdk.enhanced.dynamodb.testing;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.lang.UnsupportedOperationException;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;

public class FakeKmsClient implements KmsClient {
    private static final SecureRandom rnd = new SecureRandom();
    private static final String ACCOUNT_ID = "01234567890";
    private final Map<DecryptMapKey, DecryptResponse> responses = new HashMap<>();

    public CreateKeyResponse createKey(software.amazon.awssdk.services.kms.model.CreateKeyRequest req) throws AwsServiceException, SdkClientException, KmsException {
        String keyId = UUID.randomUUID().toString();
        String arn = "arn:aws:testing:kms:" + ACCOUNT_ID + ":key/" + keyId;
        return CreateKeyResponse.builder()
                .keyMetadata(
                        KeyMetadata.builder()
                                .awsAccountId(ACCOUNT_ID)
                                .creationDate(Instant.now())
                                .description(req.description())
                                .enabled(true)
                                .keyId(keyId)
                                .keyUsage(KeyUsageType.ENCRYPT_DECRYPT)
                                .arn(arn)
                                .build())
                .build();
    }

    @Override
    public DecryptResponse decrypt(DecryptRequest req) throws InvalidCiphertextException {
        DecryptResponse result = responses.get(new DecryptMapKey(req));
        if (result != null) {
            return result;
        } else {
            throw InvalidCiphertextException.builder()
                    .message("Invalid Ciphertext")
                    .build();
        }
    }

    @Override
    public EncryptResponse encrypt(EncryptRequest req) {
        final byte[] cipherText = new byte[512];
        rnd.nextBytes(cipherText);
        DecryptResponse dec = DecryptResponse.builder()
                .keyId(req.keyId())
                .plaintext(req.plaintext())
                .build();
        SdkBytes cipherTextBytes = SdkBytes.fromByteArray(cipherText);

        responses.put(new DecryptMapKey(cipherTextBytes, req.encryptionContext()), dec);

        return EncryptResponse.builder()
                .ciphertextBlob(cipherTextBytes)
                .keyId(req.keyId())
                .build();
    }

    @Override
    public GenerateDataKeyResponse generateDataKey(GenerateDataKeyRequest req) {
        byte[] pt;
        if (req.keySpec() != null) {
            if (req.keySpec() == DataKeySpec.AES_256) {
                pt = new byte[32];
            } else if (req.keySpec() == DataKeySpec.AES_128) {
                pt = new byte[16];
            } else {
                throw new UnsupportedOperationException();
            }
        } else {
            pt = new byte[req.numberOfBytes()];
        }
        rnd.nextBytes(pt);
        SdkBytes ptBytes = SdkBytes.fromByteArray(pt);
        EncryptResponse encryptResponse =
                encrypt(
                        EncryptRequest.builder()
                                .keyId(req.keyId())
                                .plaintext(ptBytes)
                                .encryptionContext(req.encryptionContext())
                                .build());
        return GenerateDataKeyResponse.builder()
                .keyId(req.keyId())
                .ciphertextBlob(encryptResponse.ciphertextBlob())
                .plaintext(ptBytes).build();
    }

    @Override
    public GenerateDataKeyWithoutPlaintextResponse generateDataKeyWithoutPlaintext(
            GenerateDataKeyWithoutPlaintextRequest req) {
        GenerateDataKeyResponse generateDataKey =
                generateDataKey(
                        GenerateDataKeyRequest.builder()
                                .encryptionContext(req.encryptionContext())
                                .numberOfBytes(req.numberOfBytes()).build());
        return GenerateDataKeyWithoutPlaintextResponse.builder()
                .ciphertextBlob(generateDataKey.ciphertextBlob())
                .keyId(req.keyId()).build();
    }


    public void dump() {
        System.out.println(responses);
    }

    public Map<String, String> getSingleEc() {
        if (responses.size() != 1) {
            throw new IllegalStateException("Unexpected number of ciphertexts");
        }
        for (final DecryptMapKey k : responses.keySet()) {
            return k.ec;
        }
        throw new IllegalStateException("Unexpected number of ciphertexts");
    }

    @Override
    public final String serviceName() {
        return SERVICE_NAME;
    }

    @Override
    public void close() {

    }

    private static class DecryptMapKey {
        private final ByteBuffer cipherText;
        private final Map<String, String> ec;

        public DecryptMapKey(DecryptRequest req) {
            cipherText = req.ciphertextBlob().asByteBuffer();
            if (req.encryptionContext() != null) {
                ec = Collections.unmodifiableMap(new HashMap<String, String>(req.encryptionContext()));
            } else {
                ec = Collections.emptyMap();
            }
        }

        public DecryptMapKey(SdkBytes ct, Map<String, String> ec) {
            cipherText = ct.asByteBuffer().asReadOnlyBuffer();
            if (ec != null) {
                this.ec = Collections.unmodifiableMap(new HashMap<String, String>(ec));
            } else {
                this.ec = Collections.emptyMap();
            }
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((cipherText == null) ? 0 : cipherText.hashCode());
            result = prime * result + ((ec == null) ? 0 : ec.hashCode());
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (obj == null) return false;
            if (getClass() != obj.getClass()) return false;
            DecryptMapKey other = (DecryptMapKey) obj;
            if (cipherText == null) {
                if (other.cipherText != null) return false;
            } else if (!cipherText.equals(other.cipherText)) return false;
            if (ec == null) {
                if (other.ec != null) return false;
            } else if (!ec.equals(other.ec)) return false;
            return true;
        }

        @Override
        public String toString() {
            return "DecryptMapKey [cipherText=" + cipherText + ", ec=" + ec + "]";
        }
    }
}
