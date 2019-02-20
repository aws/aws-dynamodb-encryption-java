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
package com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers;

import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionContext;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.DecryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.EncryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.internal.Utils;
import com.amazonaws.util.Base64;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.SecretKeyEntry;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;
import static org.testng.AssertJUnit.assertNull;
import static org.testng.AssertJUnit.fail;

public class KeyStoreMaterialsProviderTest {
    private static final String certPem =
            "MIIDbTCCAlWgAwIBAgIJANdRvzVsW1CIMA0GCSqGSIb3DQEBBQUAME0xCzAJBgNV" +
                    "BAYTAlVTMRMwEQYDVQQIDApXYXNoaW5ndG9uMQwwCgYDVQQKDANBV1MxGzAZBgNV" +
                    "BAMMEktleVN0b3JlIFRlc3QgQ2VydDAeFw0xMzA1MDgyMzMyMjBaFw0xMzA2MDcy" +
                    "MzMyMjBaME0xCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApXYXNoaW5ndG9uMQwwCgYD" +
                    "VQQKDANBV1MxGzAZBgNVBAMMEktleVN0b3JlIFRlc3QgQ2VydDCCASIwDQYJKoZI" +
                    "hvcNAQEBBQADggEPADCCAQoCggEBAJ8+umOX8x/Ma4OZishtYpcA676bwK5KScf3" +
                    "w+YGM37L12KTdnOyieiGtRW8p0fS0YvnhmVTvaky09I33bH+qy9gliuNL2QkyMxp" +
                    "uu1IwkTKKuB67CaKT6osYJLFxV/OwHcaZnTszzDgbAVg/Z+8IZxhPgxMzMa+7nDn" +
                    "hEm9Jd+EONq3PnRagnFeLNbMIePprdJzXHyNNiZKRRGQ/Mo9rr7mqMLSKnFNsmzB" +
                    "OIfeZM8nXeg+cvlmtXl72obwnGGw2ksJfaxTPm4eEhzRoAgkbjPPLHbwiJlc+GwF" +
                    "i8kh0Y3vQTj/gOFE4nzipkm7ux1lsGHNRVpVDWpjNd8Fl9JFELkCAwEAAaNQME4w" +
                    "HQYDVR0OBBYEFM0oGUuFAWlLXZaMXoJgGZxWqfOxMB8GA1UdIwQYMBaAFM0oGUuF" +
                    "AWlLXZaMXoJgGZxWqfOxMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEB" +
                    "AAXCsXeC8ZRxovP0Wc6C5qv3d7dtgJJVzHwoIRt2YR3yScBa1XI40GKT80jP3MYH" +
                    "8xMu3mBQtcYrgRKZBy4GpHAyxoFTnPcuzq5Fg7dw7fx4E4OKIbWOahdxwtbVxQfZ" +
                    "UHnGG88Z0bq2twj7dALGyJhUDdiccckJGmJPOFMzjqsvoAu0n/p7eS6y5WZ5ewqw" +
                    "p7VwYOP3N9wVV7Podmkh1os+eCcp9GoFf0MHBMFXi2Ps2azKx8wHRIA5D1MZv/Va" +
                    "4L4/oTBKCjORpFlP7EhMksHBYnjqXLDP6awPMAgQNYB5J9zX6GfJsAgly3t4Rjr5" +
                    "cLuNYBmRuByFGo+SOdrj6D8=";
    private static final String keyPem =
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCfPrpjl/MfzGuD" +
                    "mYrIbWKXAOu+m8CuSknH98PmBjN+y9dik3ZzsonohrUVvKdH0tGL54ZlU72pMtPS" +
                    "N92x/qsvYJYrjS9kJMjMabrtSMJEyirgeuwmik+qLGCSxcVfzsB3GmZ07M8w4GwF" +
                    "YP2fvCGcYT4MTMzGvu5w54RJvSXfhDjatz50WoJxXizWzCHj6a3Sc1x8jTYmSkUR" +
                    "kPzKPa6+5qjC0ipxTbJswTiH3mTPJ13oPnL5ZrV5e9qG8JxhsNpLCX2sUz5uHhIc" +
                    "0aAIJG4zzyx28IiZXPhsBYvJIdGN70E4/4DhROJ84qZJu7sdZbBhzUVaVQ1qYzXf" +
                    "BZfSRRC5AgMBAAECggEBAJMwx9eGe5LIwBfDtCPN93LbxwtHq7FtuQS8XrYexTpN" +
                    "76eN5c7LF+11lauh1HzuwAEw32iJHqVl9aQ5PxFm85O3ExbuSP+ngHJwx/bLacVr" +
                    "mHYlKGH3Net1WU5Qvz7vO7bbEBjDSj9DMJVIMSWUHv0MZO25jw2lLX/ufrgpvPf7" +
                    "KXSgXg/8uV7PbnTbBDNlg02u8eOc+IbH4O8XDKAhD+YQ8AE3pxtopJbb912U/cJs" +
                    "Y0hQ01zbkWYH7wL9BeQmR7+TEjjtr/IInNjnXmaOmSX867/rTSTuozaVrl1Ce7r8" +
                    "EmUDg9ZLZeKfoNYovMy08wnxWVX2J+WnNDjNiSOm+IECgYEA0v3jtGrOnKbd0d9E" +
                    "dbyIuhjgnwp+UsgALIiBeJYjhFS9NcWgs+02q/0ztqOK7g088KBBQOmiA+frLIVb" +
                    "uNCt/3jF6kJvHYkHMZ0eBEstxjVSM2UcxzJ6ceHZ68pmrru74382TewVosxccNy0" +
                    "glsUWNN0t5KQDcetaycRYg50MmcCgYEAwTb8klpNyQE8AWxVQlbOIEV24iarXxex" +
                    "7HynIg9lSeTzquZOXjp0m5omQ04psil2gZ08xjiudG+Dm7QKgYQcxQYUtZPQe15K" +
                    "m+2hQM0jA7tRfM1NAZHoTmUlYhzRNX6GWAqQXOgjOqBocT4ySBXRaSQq9zuZu36s" +
                    "fI17knap798CgYArDa2yOf0xEAfBdJqmn7MSrlLfgSenwrHuZGhu78wNi7EUUOBq" +
                    "9qOqUr+DrDmEO+VMgJbwJPxvaZqeehPuUX6/26gfFjFQSI7UO+hNHf4YLPc6D47g" +
                    "wtcjd9+c8q8jRqGfWWz+V4dOsf7G9PJMi0NKoNN3RgvpE+66J72vUZ26TwKBgEUq" +
                    "DdfGA7pEetp3kT2iHT9oHlpuRUJRFRv2s015/WQqVR+EOeF5Q2zADZpiTIK+XPGg" +
                    "+7Rpbem4UYBXPruGM1ZECv3E4AiJhGO0+Nhdln8reswWIc7CEEqf4nXwouNnW2gA" +
                    "wBTB9Hp0GW8QOKedR80/aTH/X9TCT7R2YRnY6JQ5AoGBAKjgPySgrNDhlJkW7jXR" +
                    "WiGpjGSAFPT9NMTvEHDo7oLTQ8AcYzcGQ7ISMRdVXR6GJOlFVsH4NLwuHGtcMTPK" +
                    "zoHbPHJyOn1SgC5tARD/1vm5CsG2hATRpWRQCTJFg5VRJ4R7Pz+HuxY4SoABcPQd" +
                    "K+MP8GlGqTldC6NaB1s7KuAX";

    private static SecretKey encryptionKey;
    private static SecretKey macKey;
    private static KeyStore keyStore;
    private static final String password = "Password";
    private static final PasswordProtection passwordProtection = new PasswordProtection(password.toCharArray());

    private Map<String, String> description;
    private EncryptionContext ctx;
    private static PrivateKey privateKey;
    private static Certificate certificate;


    @BeforeClass
    public static void setUpBeforeClass() throws Exception {

        KeyGenerator macGen = KeyGenerator.getInstance("HmacSHA256");
        macGen.init(256, Utils.getRng());
        macKey = macGen.generateKey();

        KeyGenerator aesGen = KeyGenerator.getInstance("AES");
        aesGen.init(128, Utils.getRng());
        encryptionKey = aesGen.generateKey();

        keyStore = KeyStore.getInstance("jceks");
        keyStore.load(null, password.toCharArray());

        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec rsaSpec = new PKCS8EncodedKeySpec(Base64.decode(keyPem));
        privateKey = kf.generatePrivate(rsaSpec);
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        certificate = cf.generateCertificate(new ByteArrayInputStream(Base64.decode(certPem)));


        keyStore.setEntry("enc", new SecretKeyEntry(encryptionKey), passwordProtection);
        keyStore.setEntry("sig", new SecretKeyEntry(macKey), passwordProtection);
        keyStore.setEntry("enc-a", new PrivateKeyEntry(privateKey, new Certificate[]{certificate}), passwordProtection);
        keyStore.setEntry("sig-a", new PrivateKeyEntry(privateKey, new Certificate[]{certificate}), passwordProtection);
        keyStore.setCertificateEntry("trustedCert", certificate);
    }

    @BeforeMethod
    public void setUp() {
        description = new HashMap<String, String>();
        description.put("TestKey", "test value");
        description = Collections.unmodifiableMap(description);
        ctx = new EncryptionContext.Builder().build();
    }

    @Test
    @SuppressWarnings("unchecked")
    public void simpleSymMac() throws Exception {
        KeyStoreMaterialsProvider prov = new KeyStoreMaterialsProvider(keyStore, "enc", "sig", passwordProtection, passwordProtection, Collections.EMPTY_MAP);
        EncryptionMaterials encryptionMaterials = prov.getEncryptionMaterials(ctx);
        assertEquals(encryptionKey, encryptionMaterials.getEncryptionKey());
        assertEquals(macKey, encryptionMaterials.getSigningKey());

        assertEquals(encryptionKey, prov.getDecryptionMaterials(ctx(encryptionMaterials)).getDecryptionKey());
        assertEquals(macKey, prov.getDecryptionMaterials(ctx(encryptionMaterials)).getVerificationKey());
    }

    @Test
    @SuppressWarnings("unchecked")
    public void simpleSymSig() throws Exception {
        KeyStoreMaterialsProvider prov = new KeyStoreMaterialsProvider(keyStore, "enc", "sig-a", passwordProtection, passwordProtection, Collections.EMPTY_MAP);
        EncryptionMaterials encryptionMaterials = prov.getEncryptionMaterials(ctx);
        assertEquals(encryptionKey, encryptionMaterials.getEncryptionKey());
        assertEquals(privateKey, encryptionMaterials.getSigningKey());

        assertEquals(encryptionKey, prov.getDecryptionMaterials(ctx(encryptionMaterials)).getDecryptionKey());
        assertEquals(certificate.getPublicKey(), prov.getDecryptionMaterials(ctx(encryptionMaterials)).getVerificationKey());
    }

    @Test
    public void equalSymDescMac() throws Exception {
        KeyStoreMaterialsProvider prov = new KeyStoreMaterialsProvider(keyStore, "enc", "sig", passwordProtection, passwordProtection, description);
        EncryptionMaterials encryptionMaterials = prov.getEncryptionMaterials(ctx);
        assertEquals(encryptionKey, encryptionMaterials.getEncryptionKey());
        assertEquals(macKey, encryptionMaterials.getSigningKey());

        assertEquals(encryptionKey, prov.getDecryptionMaterials(ctx(encryptionMaterials)).getDecryptionKey());
        assertEquals(macKey, prov.getDecryptionMaterials(ctx(encryptionMaterials)).getVerificationKey());
    }

    @Test
    public void superSetSymDescMac() throws Exception {
        KeyStoreMaterialsProvider prov = new KeyStoreMaterialsProvider(keyStore, "enc", "sig", passwordProtection, passwordProtection, description);
        EncryptionMaterials encryptionMaterials = prov.getEncryptionMaterials(ctx);
        assertEquals(encryptionKey, encryptionMaterials.getEncryptionKey());
        assertEquals(macKey, encryptionMaterials.getSigningKey());
        Map<String, String> tmpDesc = new HashMap<String, String>(encryptionMaterials.getMaterialDescription());
        tmpDesc.put("randomValue", "random");

        assertEquals(encryptionKey, prov.getDecryptionMaterials(ctx(tmpDesc)).getDecryptionKey());
        assertEquals(macKey, prov.getDecryptionMaterials(ctx(tmpDesc)).getVerificationKey());
    }

    @Test
    @SuppressWarnings("unchecked")
    public void subSetSymDescMac() throws Exception {
        KeyStoreMaterialsProvider prov = new KeyStoreMaterialsProvider(keyStore, "enc", "sig", passwordProtection, passwordProtection, description);
        EncryptionMaterials encryptionMaterials = prov.getEncryptionMaterials(ctx);
        assertEquals(encryptionKey, encryptionMaterials.getEncryptionKey());
        assertEquals(macKey, encryptionMaterials.getSigningKey());

        assertNull(prov.getDecryptionMaterials(ctx(Collections.EMPTY_MAP)));
    }


    @Test
    public void noMatchSymDescMac() throws Exception {
        KeyStoreMaterialsProvider prov = new KeyStoreMaterialsProvider(keyStore, "enc", "sig", passwordProtection, passwordProtection, description);
        EncryptionMaterials encryptionMaterials = prov.getEncryptionMaterials(ctx);
        assertEquals(encryptionKey, encryptionMaterials.getEncryptionKey());
        assertEquals(macKey, encryptionMaterials.getSigningKey());
        Map<String, String> tmpDesc = new HashMap<String, String>();
        tmpDesc.put("randomValue", "random");

        assertNull(prov.getDecryptionMaterials(ctx(tmpDesc)));
    }

    @Test
    public void testRefresh() throws Exception {
        // Mostly make sure we don't throw an exception
        KeyStoreMaterialsProvider prov = new KeyStoreMaterialsProvider(keyStore, "enc", "sig", passwordProtection, passwordProtection, description);
        prov.refresh();
    }

    @Test
    public void asymSimpleMac() throws Exception {
        KeyStoreMaterialsProvider prov = new KeyStoreMaterialsProvider(keyStore, "enc-a", "sig", passwordProtection, passwordProtection, description);
        EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
        SecretKey encryptionKey = eMat.getEncryptionKey();
        assertNotNull(encryptionKey);
        assertEquals(macKey, eMat.getSigningKey());

        DecryptionMaterials dMat = prov.getDecryptionMaterials(ctx(eMat));
        assertEquals(encryptionKey, dMat.getDecryptionKey());
        assertEquals(macKey, dMat.getVerificationKey());
    }

    @Test
    public void asymSimpleSig() throws Exception {
        KeyStoreMaterialsProvider prov = new KeyStoreMaterialsProvider(keyStore, "enc-a", "sig-a", passwordProtection, passwordProtection, description);
        EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
        SecretKey encryptionKey = eMat.getEncryptionKey();
        assertNotNull(encryptionKey);
        assertEquals(privateKey, eMat.getSigningKey());

        DecryptionMaterials dMat = prov.getDecryptionMaterials(ctx(eMat));
        assertEquals(encryptionKey, dMat.getDecryptionKey());
        assertEquals(certificate.getPublicKey(), dMat.getVerificationKey());
    }

    @Test
    public void asymSigVerifyOnly() throws Exception {
        KeyStoreMaterialsProvider prov = new KeyStoreMaterialsProvider(keyStore, "enc-a", "trustedCert", passwordProtection, null, description);
        EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
        SecretKey encryptionKey = eMat.getEncryptionKey();
        assertNotNull(encryptionKey);
        assertNull(eMat.getSigningKey());

        DecryptionMaterials dMat = prov.getDecryptionMaterials(ctx(eMat));
        assertEquals(encryptionKey, dMat.getDecryptionKey());
        assertEquals(certificate.getPublicKey(), dMat.getVerificationKey());
    }

    @Test
    public void asymSigEncryptOnly() throws Exception {
        KeyStoreMaterialsProvider prov = new KeyStoreMaterialsProvider(keyStore, "trustedCert", "sig-a", null, passwordProtection, description);
        EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
        SecretKey encryptionKey = eMat.getEncryptionKey();
        assertNotNull(encryptionKey);
        assertEquals(privateKey, eMat.getSigningKey());

        try {
            prov.getDecryptionMaterials(ctx(eMat));
            fail("Expected exception");
        } catch (IllegalStateException ex) {
            assertEquals("No private decryption key provided.", ex.getMessage());
        }
    }

    private static EncryptionContext ctx(EncryptionMaterials mat) {
        return ctx(mat.getMaterialDescription());
    }

    private static EncryptionContext ctx(Map<String, String> desc) {
        return new EncryptionContext.Builder()
                .withMaterialDescription(desc).build();
    }
}
