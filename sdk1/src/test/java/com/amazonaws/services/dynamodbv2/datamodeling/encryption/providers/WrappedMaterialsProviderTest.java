package com.amazonaws.services.dynamodbv2.datamodeling.encryption.providers;

import com.amazonaws.services.dynamodbv2.datamodeling.encryption.EncryptionContext;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.DecryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.EncryptionMaterials;
import com.amazonaws.services.dynamodbv2.datamodeling.encryption.materials.WrappedRawMaterials;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertFalse;
import static org.testng.AssertJUnit.assertNotNull;

public class WrappedMaterialsProviderTest {
    private static SecretKey symEncryptionKey;
    private static SecretKey macKey;
    private static KeyPair sigPair;
    private static KeyPair encryptionPair;
    private static SecureRandom rnd;
    private Map<String, String> description;
    private EncryptionContext ctx;

    @BeforeClass
    public static void setUpClass() throws NoSuchAlgorithmException {
        rnd = new SecureRandom();
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048, rnd);
        sigPair = rsaGen.generateKeyPair();
        encryptionPair = rsaGen.generateKeyPair();

        KeyGenerator aesGen = KeyGenerator.getInstance("AES");
        aesGen.init(128, rnd);
        symEncryptionKey = aesGen.generateKey();

        KeyGenerator macGen = KeyGenerator.getInstance("HmacSHA256");
        macGen.init(256, rnd);
        macKey = macGen.generateKey();
    }

    @BeforeMethod
    public void setUp() {
        description = new HashMap<String, String>();
        description.put("TestKey", "test value");
        ctx = new EncryptionContext.Builder().build();
    }

    @Test
    public void simpleMac() throws GeneralSecurityException {
        WrappedMaterialsProvider prov = new WrappedMaterialsProvider(symEncryptionKey, symEncryptionKey, macKey, Collections.emptyMap());

        EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
        SecretKey contentEncryptionKey = eMat.getEncryptionKey();
        assertNotNull(contentEncryptionKey);
        assertEquals(macKey, eMat.getSigningKey());

        DecryptionMaterials dMat = prov.getDecryptionMaterials(ctx(eMat));
        assertEquals(contentEncryptionKey, dMat.getDecryptionKey());
        assertEquals(macKey, dMat.getVerificationKey());
    }

    @Test
    public void simpleSigPair() throws GeneralSecurityException {
        WrappedMaterialsProvider prov = new WrappedMaterialsProvider(symEncryptionKey, symEncryptionKey, sigPair, Collections.emptyMap());

        EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
        SecretKey contentEncryptionKey = eMat.getEncryptionKey();
        assertNotNull(contentEncryptionKey);
        assertEquals(sigPair.getPrivate(), eMat.getSigningKey());

        DecryptionMaterials dMat = prov.getDecryptionMaterials(ctx(eMat));
        assertEquals(contentEncryptionKey, dMat.getDecryptionKey());
        assertEquals(sigPair.getPublic(), dMat.getVerificationKey());
    }

    @Test
    public void randomEnvelopeKeys() throws GeneralSecurityException {
        WrappedMaterialsProvider prov = new WrappedMaterialsProvider(symEncryptionKey, symEncryptionKey, macKey, Collections.emptyMap());

        EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
        SecretKey contentEncryptionKey = eMat.getEncryptionKey();
        assertNotNull(contentEncryptionKey);
        assertEquals(macKey, eMat.getSigningKey());

        EncryptionMaterials eMat2 = prov.getEncryptionMaterials(ctx);
        SecretKey contentEncryptionKey2 = eMat2.getEncryptionKey();
        assertEquals(macKey, eMat.getSigningKey());

        assertFalse("Envelope keys must be different", contentEncryptionKey.equals(contentEncryptionKey2));
    }

    @Test
    public void testRefresh() {
        // This does nothing, make sure we don't throw an exception.
        WrappedMaterialsProvider prov = new WrappedMaterialsProvider(symEncryptionKey, symEncryptionKey, macKey, Collections.emptyMap());
        prov.refresh();
    }

    @Test
    public void wrapUnwrapAsymMatExplicitWrappingAlgorithmPkcs1() throws GeneralSecurityException {
        Map<String, String> desc = new HashMap<String, String>();
        desc.put(WrappedRawMaterials.KEY_WRAPPING_ALGORITHM, "RSA/ECB/PKCS1Padding");

        WrappedMaterialsProvider prov = new WrappedMaterialsProvider(encryptionPair.getPublic(), encryptionPair.getPrivate(), sigPair, desc);

        EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
        SecretKey contentEncryptionKey = eMat.getEncryptionKey();
        assertNotNull(contentEncryptionKey);
        assertEquals(sigPair.getPrivate(), eMat.getSigningKey());

        DecryptionMaterials dMat = prov.getDecryptionMaterials(ctx(eMat));
        assertEquals("RSA/ECB/PKCS1Padding", eMat.getMaterialDescription().get(WrappedRawMaterials.KEY_WRAPPING_ALGORITHM));
        assertEquals(contentEncryptionKey, dMat.getDecryptionKey());
        assertEquals(sigPair.getPublic(), dMat.getVerificationKey());
    }

    @Test
    public void wrapUnwrapAsymMatExplicitWrappingAlgorithmPkcs2() throws GeneralSecurityException {
        Map<String, String> desc = new HashMap<String, String>();
        desc.put(WrappedRawMaterials.KEY_WRAPPING_ALGORITHM, "RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

        WrappedMaterialsProvider prov = new WrappedMaterialsProvider(encryptionPair.getPublic(), encryptionPair.getPrivate(), sigPair, desc);

        EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
        SecretKey contentEncryptionKey = eMat.getEncryptionKey();
        assertNotNull(contentEncryptionKey);
        assertEquals(sigPair.getPrivate(), eMat.getSigningKey());

        DecryptionMaterials dMat = prov.getDecryptionMaterials(ctx(eMat));
        assertEquals("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", eMat.getMaterialDescription().get(WrappedRawMaterials.KEY_WRAPPING_ALGORITHM));
        assertEquals(contentEncryptionKey, dMat.getDecryptionKey());
        assertEquals(sigPair.getPublic(), dMat.getVerificationKey());
    }

    @Test
    public void wrapUnwrapAsymMatExplicitContentKeyAlgorithm() throws GeneralSecurityException {
        Map<String, String> desc = new HashMap<String, String>();
        desc.put(WrappedRawMaterials.CONTENT_KEY_ALGORITHM, "AES");

        WrappedMaterialsProvider prov = new WrappedMaterialsProvider(encryptionPair.getPublic(), encryptionPair.getPrivate(), sigPair, Collections.emptyMap());

        EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
        SecretKey contentEncryptionKey = eMat.getEncryptionKey();
        assertNotNull(contentEncryptionKey);
        assertEquals("AES", contentEncryptionKey.getAlgorithm());
        assertEquals("AES", eMat.getMaterialDescription().get(WrappedRawMaterials.CONTENT_KEY_ALGORITHM));
        assertEquals(sigPair.getPrivate(), eMat.getSigningKey());

        DecryptionMaterials dMat = prov.getDecryptionMaterials(ctx(eMat));
        assertEquals("AES", dMat.getMaterialDescription().get(WrappedRawMaterials.CONTENT_KEY_ALGORITHM));
        assertEquals(contentEncryptionKey, dMat.getDecryptionKey());
        assertEquals(sigPair.getPublic(), dMat.getVerificationKey());
    }

    @Test
    public void wrapUnwrapAsymMatExplicitContentKeyLength128() throws GeneralSecurityException {
        Map<String, String> desc = new HashMap<String, String>();
        desc.put(WrappedRawMaterials.CONTENT_KEY_ALGORITHM, "AES/128");

        WrappedMaterialsProvider prov = new WrappedMaterialsProvider(encryptionPair.getPublic(), encryptionPair.getPrivate(), sigPair, desc);

        EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
        SecretKey contentEncryptionKey = eMat.getEncryptionKey();
        assertNotNull(contentEncryptionKey);
        assertEquals("AES", contentEncryptionKey.getAlgorithm());
        assertEquals("AES", eMat.getMaterialDescription().get(WrappedRawMaterials.CONTENT_KEY_ALGORITHM));
        assertEquals(16, contentEncryptionKey.getEncoded().length); // 128 Bits
        assertEquals(sigPair.getPrivate(), eMat.getSigningKey());

        DecryptionMaterials dMat = prov.getDecryptionMaterials(ctx(eMat));
        assertEquals("AES", dMat.getMaterialDescription().get(WrappedRawMaterials.CONTENT_KEY_ALGORITHM));
        assertEquals(contentEncryptionKey, dMat.getDecryptionKey());
        assertEquals(sigPair.getPublic(), dMat.getVerificationKey());
    }

    @Test
    public void wrapUnwrapAsymMatExplicitContentKeyLength256() throws GeneralSecurityException {
        Map<String, String> desc = new HashMap<String, String>();
        desc.put(WrappedRawMaterials.CONTENT_KEY_ALGORITHM, "AES/256");

        WrappedMaterialsProvider prov = new WrappedMaterialsProvider(encryptionPair.getPublic(), encryptionPair.getPrivate(), sigPair, desc);

        EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
        SecretKey contentEncryptionKey = eMat.getEncryptionKey();
        assertNotNull(contentEncryptionKey);
        assertEquals("AES", contentEncryptionKey.getAlgorithm());
        assertEquals("AES", eMat.getMaterialDescription().get(WrappedRawMaterials.CONTENT_KEY_ALGORITHM));
        assertEquals(32, contentEncryptionKey.getEncoded().length); // 256 Bits
        assertEquals(sigPair.getPrivate(), eMat.getSigningKey());

        DecryptionMaterials dMat = prov.getDecryptionMaterials(ctx(eMat));
        assertEquals("AES", dMat.getMaterialDescription().get(WrappedRawMaterials.CONTENT_KEY_ALGORITHM));
        assertEquals(contentEncryptionKey, dMat.getDecryptionKey());
        assertEquals(sigPair.getPublic(), dMat.getVerificationKey());
    }

    @Test
    public void unwrapAsymMatExplicitEncAlgAes128() throws GeneralSecurityException {
        Map<String, String> desc = new HashMap<String, String>();
        desc.put(WrappedRawMaterials.CONTENT_KEY_ALGORITHM, "AES/128");

        WrappedMaterialsProvider prov = new WrappedMaterialsProvider(encryptionPair.getPublic(), encryptionPair.getPrivate(), sigPair, desc);

        // Get materials we can test unwrapping on
        EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);

        // Ensure "AES/128" on the created materials creates the expected key
        Map<String, String> aes128Desc = eMat.getMaterialDescription();
        aes128Desc.put(WrappedRawMaterials.CONTENT_KEY_ALGORITHM, "AES/128");
        EncryptionContext aes128Ctx = new EncryptionContext.Builder()
                .withMaterialDescription(aes128Desc).build();

        DecryptionMaterials dMat = prov.getDecryptionMaterials(aes128Ctx);
        assertEquals("AES/128", dMat.getMaterialDescription().get(WrappedRawMaterials.CONTENT_KEY_ALGORITHM));
        assertEquals("AES", dMat.getDecryptionKey().getAlgorithm());
        assertEquals(eMat.getEncryptionKey(), dMat.getDecryptionKey());
        assertEquals(sigPair.getPublic(), dMat.getVerificationKey());
    }

    @Test
    public void unwrapAsymMatExplicitEncAlgAes256() throws GeneralSecurityException {
        Map<String, String> desc = new HashMap<String, String>();
        desc.put(WrappedRawMaterials.CONTENT_KEY_ALGORITHM, "AES/256");

        WrappedMaterialsProvider prov = new WrappedMaterialsProvider(encryptionPair.getPublic(), encryptionPair.getPrivate(), sigPair, desc);

        // Get materials we can test unwrapping on
        EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);

        // Ensure "AES/256" on the created materials creates the expected key
        Map<String, String> aes256Desc = eMat.getMaterialDescription();
        aes256Desc.put(WrappedRawMaterials.CONTENT_KEY_ALGORITHM, "AES/256");
        EncryptionContext aes256Ctx = new EncryptionContext.Builder()
                .withMaterialDescription(aes256Desc).build();

        DecryptionMaterials dMat = prov.getDecryptionMaterials(aes256Ctx);
        assertEquals("AES/256", dMat.getMaterialDescription().get(WrappedRawMaterials.CONTENT_KEY_ALGORITHM));
        assertEquals("AES", dMat.getDecryptionKey().getAlgorithm());
        assertEquals(eMat.getEncryptionKey(), dMat.getDecryptionKey());
        assertEquals(sigPair.getPublic(), dMat.getVerificationKey());
    }

    @Test
    public void wrapUnwrapSymMatExplicitContentKeyAlgorithm() throws GeneralSecurityException {
        Map<String, String> desc = new HashMap<String, String>();
        desc.put(WrappedRawMaterials.CONTENT_KEY_ALGORITHM, "AES");

        WrappedMaterialsProvider prov = new WrappedMaterialsProvider(symEncryptionKey, symEncryptionKey, macKey, desc);

        EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
        SecretKey contentEncryptionKey = eMat.getEncryptionKey();
        assertNotNull(contentEncryptionKey);
        assertEquals("AES", contentEncryptionKey.getAlgorithm());
        assertEquals("AES", eMat.getMaterialDescription().get(WrappedRawMaterials.CONTENT_KEY_ALGORITHM));
        assertEquals(macKey, eMat.getSigningKey());

        DecryptionMaterials dMat = prov.getDecryptionMaterials(ctx(eMat));
        assertEquals("AES", dMat.getMaterialDescription().get(WrappedRawMaterials.CONTENT_KEY_ALGORITHM));
        assertEquals(contentEncryptionKey, dMat.getDecryptionKey());
        assertEquals(macKey, dMat.getVerificationKey());
    }

    @Test
    public void wrapUnwrapSymMatExplicitContentKeyLength128() throws GeneralSecurityException {
        Map<String, String> desc = new HashMap<String, String>();
        desc.put(WrappedRawMaterials.CONTENT_KEY_ALGORITHM, "AES/128");

        WrappedMaterialsProvider prov = new WrappedMaterialsProvider(symEncryptionKey, symEncryptionKey, macKey, desc);

        EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
        SecretKey contentEncryptionKey = eMat.getEncryptionKey();
        assertNotNull(contentEncryptionKey);
        assertEquals("AES", contentEncryptionKey.getAlgorithm());
        assertEquals("AES", eMat.getMaterialDescription().get(WrappedRawMaterials.CONTENT_KEY_ALGORITHM));
        assertEquals(16, contentEncryptionKey.getEncoded().length); // 128 Bits
        assertEquals(macKey, eMat.getSigningKey());

        DecryptionMaterials dMat = prov.getDecryptionMaterials(ctx(eMat));
        assertEquals("AES", dMat.getMaterialDescription().get(WrappedRawMaterials.CONTENT_KEY_ALGORITHM));
        assertEquals(contentEncryptionKey, dMat.getDecryptionKey());
        assertEquals(macKey, dMat.getVerificationKey());
    }

    @Test
    public void wrapUnwrapSymMatExplicitContentKeyLength256() throws GeneralSecurityException {
        Map<String, String> desc = new HashMap<String, String>();
        desc.put(WrappedRawMaterials.CONTENT_KEY_ALGORITHM, "AES/256");

        WrappedMaterialsProvider prov = new WrappedMaterialsProvider(symEncryptionKey, symEncryptionKey, macKey, desc);

        EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);
        SecretKey contentEncryptionKey = eMat.getEncryptionKey();
        assertNotNull(contentEncryptionKey);
        assertEquals("AES", contentEncryptionKey.getAlgorithm());
        assertEquals("AES", eMat.getMaterialDescription().get(WrappedRawMaterials.CONTENT_KEY_ALGORITHM));
        assertEquals(32, contentEncryptionKey.getEncoded().length); // 256 Bits
        assertEquals(macKey, eMat.getSigningKey());

        DecryptionMaterials dMat = prov.getDecryptionMaterials(ctx(eMat));
        assertEquals("AES", dMat.getMaterialDescription().get(WrappedRawMaterials.CONTENT_KEY_ALGORITHM));
        assertEquals(contentEncryptionKey, dMat.getDecryptionKey());
        assertEquals(macKey, dMat.getVerificationKey());
    }

    @Test
    public void unwrapSymMatExplicitEncAlgAes128() throws GeneralSecurityException {
        Map<String, String> desc = new HashMap<String, String>();
        desc.put(WrappedRawMaterials.CONTENT_KEY_ALGORITHM, "AES/128");

        WrappedMaterialsProvider prov = new WrappedMaterialsProvider(symEncryptionKey, symEncryptionKey, macKey, desc);

        // Get materials we can test unwrapping on
        EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);

        // Ensure "AES/128" on the created materials creates the expected key
        Map<String, String> aes128Desc = eMat.getMaterialDescription();
        aes128Desc.put(WrappedRawMaterials.CONTENT_KEY_ALGORITHM, "AES/128");
        EncryptionContext aes128Ctx = new EncryptionContext.Builder()
                .withMaterialDescription(aes128Desc).build();

        DecryptionMaterials dMat = prov.getDecryptionMaterials(aes128Ctx);
        assertEquals("AES/128", dMat.getMaterialDescription().get(WrappedRawMaterials.CONTENT_KEY_ALGORITHM));
        assertEquals("AES", dMat.getDecryptionKey().getAlgorithm());
        assertEquals(eMat.getEncryptionKey(), dMat.getDecryptionKey());
        assertEquals(macKey, dMat.getVerificationKey());
    }

    @Test
    public void unwrapSymMatExplicitEncAlgAes256() throws GeneralSecurityException {
        Map<String, String> desc = new HashMap<String, String>();
        desc.put(WrappedRawMaterials.CONTENT_KEY_ALGORITHM, "AES/256");

        WrappedMaterialsProvider prov = new WrappedMaterialsProvider(symEncryptionKey, symEncryptionKey, macKey, desc);

        EncryptionMaterials eMat = prov.getEncryptionMaterials(ctx);

        Map<String, String> aes256Desc = eMat.getMaterialDescription();
        aes256Desc.put(WrappedRawMaterials.CONTENT_KEY_ALGORITHM, "AES/256");
        EncryptionContext aes256Ctx = new EncryptionContext.Builder()
                .withMaterialDescription(aes256Desc).build();

        DecryptionMaterials dMat = prov.getDecryptionMaterials(aes256Ctx);
        assertEquals("AES/256", dMat.getMaterialDescription().get(WrappedRawMaterials.CONTENT_KEY_ALGORITHM));
        assertEquals("AES", dMat.getDecryptionKey().getAlgorithm());
        assertEquals(eMat.getEncryptionKey(), dMat.getDecryptionKey());
        assertEquals(macKey, dMat.getVerificationKey());
    }

    private static EncryptionContext ctx(EncryptionMaterials mat) {
        return new EncryptionContext.Builder()
                .withMaterialDescription(mat.getMaterialDescription()).build();
    }
}
