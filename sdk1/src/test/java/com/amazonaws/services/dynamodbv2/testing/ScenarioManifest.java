package com.amazonaws.services.dynamodbv2.testing;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ScenarioManifest {

  public static final String MOST_RECENT_PROVIDER_NAME = "most_recent";
  public static final String WRAPPED_PROVIDER_NAME = "wrapped";
  public static final String STATIC_PROVIDER_NAME = "static";
  public static final String AWS_KMS_PROVIDER_NAME = "awskms";
  public static final String SYMMETRIC_KEY_TYPE = "symmetric";

  public List<Scenario> scenarios;

  @JsonProperty("keys")
  public String keyDataPath;

  @JsonIgnoreProperties(ignoreUnknown = true)
  public static class Scenario {
    @JsonProperty("ciphertext")
    public String ciphertextPath;

    @JsonProperty("provider")
    public String providerName;

    public String version;

    @JsonProperty("material_name")
    public String materialName;

    public Metastore metastore;
    public Keys keys;
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  public static class Metastore {
    @JsonProperty("ciphertext")
    public String path;

    @JsonProperty("table_name")
    public String tableName;

    @JsonProperty("provider")
    public String providerName;

    public Keys keys;
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  public static class Keys {
    @JsonProperty("encrypt")
    public String encryptName;

    @JsonProperty("sign")
    public String signName;

    @JsonProperty("decrypt")
    public String decryptName;

    @JsonProperty("verify")
    public String verifyName;
  }

  public static class KeyData {
    public String material;
    public String algorithm;
    public String encoding;

    @JsonProperty("type")
    public String keyType;

    public String keyId;
  }
}
