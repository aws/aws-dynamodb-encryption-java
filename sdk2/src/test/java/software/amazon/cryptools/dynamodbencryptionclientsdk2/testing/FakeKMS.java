/*
 * Copyright 2014-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
package software.amazon.cryptools.dynamodbencryptionclientsdk2.testing;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.CreateKeyRequest;
import software.amazon.awssdk.services.kms.model.CreateKeyResponse;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyWithoutPlaintextRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyWithoutPlaintextResponse;
import software.amazon.awssdk.services.kms.model.InvalidCiphertextException;
import software.amazon.awssdk.services.kms.model.KeyMetadata;
import software.amazon.awssdk.services.kms.model.KeyUsageType;

public class FakeKMS implements KmsClient {
    private static final SecureRandom rnd = new SecureRandom();
    private static final String ACCOUNT_ID = "01234567890";
    private final Map<DecryptMapKey, DecryptResponse> results_ = new HashMap<>();

    @Override
    public CreateKeyResponse createKey(CreateKeyRequest createKeyRequest) {
        String keyId = UUID.randomUUID().toString();
        String arn = "arn:aws:testing:kms:" + ACCOUNT_ID + ":key/" + keyId;
        return CreateKeyResponse.builder()
                                .keyMetadata(KeyMetadata.builder().awsAccountId(ACCOUNT_ID)
                                    .creationDate(Instant.now())
                                    .description(createKeyRequest.description())
                                    .enabled(true)
                                    .keyId(keyId)
                                    .keyUsage(KeyUsageType.ENCRYPT_DECRYPT)
                                    .arn(arn)
                                    .build())
                                .build();
    }

    @Override
    public DecryptResponse decrypt(DecryptRequest decryptRequest) {
        DecryptResponse result = results_.get(new DecryptMapKey(decryptRequest));
        if (result != null) {
            return result;
        } else {
            throw InvalidCiphertextException.create("Invalid Ciphertext", new RuntimeException());
        }
    }

    @Override
    public EncryptResponse encrypt(EncryptRequest encryptRequest) {
        final byte[] cipherText = new byte[512];
        rnd.nextBytes(cipherText);
        DecryptResponse.Builder dec = DecryptResponse.builder();
        dec.keyId(encryptRequest.keyId())
           .plaintext(SdkBytes.fromByteBuffer(encryptRequest.plaintext().asByteBuffer().asReadOnlyBuffer()));
        ByteBuffer ctBuff = ByteBuffer.wrap(cipherText);

        results_.put(new DecryptMapKey(ctBuff, encryptRequest.encryptionContext()), dec.build());

        return EncryptResponse.builder()
                              .ciphertextBlob(SdkBytes.fromByteBuffer(ctBuff))
                              .keyId(encryptRequest.keyId())
                              .build();
    }

    @Override
    public GenerateDataKeyResponse generateDataKey(GenerateDataKeyRequest generateDataKeyRequest) {
        byte[] pt;
        if (generateDataKeyRequest.keySpec() != null) {
            if (generateDataKeyRequest.keySpec().toString().contains("256")) {
                pt = new byte[32];
            } else if (generateDataKeyRequest.keySpec().toString().contains("128")) {
                pt = new byte[16];
            } else {
                throw new UnsupportedOperationException();
            }
        } else {
            pt = new byte[generateDataKeyRequest.numberOfBytes()];
        }
        rnd.nextBytes(pt);
        ByteBuffer ptBuff = ByteBuffer.wrap(pt);
        EncryptResponse encryptresponse = encrypt(EncryptRequest.builder()
            .keyId(generateDataKeyRequest.keyId())
            .plaintext(SdkBytes.fromByteBuffer(ptBuff))
            .encryptionContext(generateDataKeyRequest.encryptionContext())
            .build());
        return GenerateDataKeyResponse.builder().keyId(generateDataKeyRequest.keyId())
                                      .ciphertextBlob(encryptresponse.ciphertextBlob())
                                      .plaintext(SdkBytes.fromByteBuffer(ptBuff))
                                      .build();
    }

    @Override
    public GenerateDataKeyWithoutPlaintextResponse generateDataKeyWithoutPlaintext(
        GenerateDataKeyWithoutPlaintextRequest req) {
        GenerateDataKeyResponse generateDataKey = generateDataKey(GenerateDataKeyRequest.builder()
                .encryptionContext(req.encryptionContext()).numberOfBytes(req.numberOfBytes()).build());
        return GenerateDataKeyWithoutPlaintextResponse.builder().ciphertextBlob(
                generateDataKey.ciphertextBlob()).keyId(req.keyId()).build();
    }

    public Map<String, String> getSingleEc() {
        if (results_.size() != 1) {
            throw new IllegalStateException("Unexpected number of ciphertexts");
        }
        for (final DecryptMapKey k : results_.keySet()) {
            return k.ec;
        }
        throw new IllegalStateException("Unexpected number of ciphertexts");
    }

    @Override
    public String serviceName() {
        return KmsClient.SERVICE_NAME;
    }

    @Override
    public void close() {
        // do nothing
    }

    private static class DecryptMapKey {
        private final ByteBuffer cipherText;
        private final Map<String, String> ec;

        public DecryptMapKey(DecryptRequest req) {
            cipherText = req.ciphertextBlob().asByteBuffer();
            if (req.encryptionContext() != null) {
                ec = Collections.unmodifiableMap(new HashMap<>(req.encryptionContext()));
            } else {
                ec = Collections.emptyMap();
            }
        }

        public DecryptMapKey(ByteBuffer ctBuff, Map<String, String> ec) {
            cipherText = ctBuff.asReadOnlyBuffer();
            if (ec != null) {
                this.ec = Collections.unmodifiableMap(new HashMap<>(ec));
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
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (getClass() != obj.getClass())
                return false;
            DecryptMapKey other = (DecryptMapKey) obj;
            if (cipherText == null) {
                if (other.cipherText != null)
                    return false;
            } else if (!cipherText.equals(other.cipherText))
                return false;
            if (ec == null) {
                if (other.ec != null)
                    return false;
            } else if (!ec.equals(other.ec))
                return false;
            return true;
        }

        @Override
        public String toString() {
            return "DecryptMapKey [cipherText=" + cipherText + ", ec=" + ec + "]";
        }
    }
}
