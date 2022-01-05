package com.amazonaws.services.dynamodbv2.testing;

import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

public class AttributeValueDeserializer extends JsonDeserializer<AttributeValue> {
  @Override
  public AttributeValue deserialize(JsonParser jp, DeserializationContext ctxt)
      throws IOException, JsonProcessingException {
    ObjectMapper objectMapper = new ObjectMapper();
    JsonNode attribute = jp.getCodec().readTree(jp);
    for (Iterator<Map.Entry<String, JsonNode>> iter = attribute.fields(); iter.hasNext(); ) {
      Map.Entry<String, JsonNode> rawAttribute = iter.next();
      // If there is more than one entry in this map, there is an error with our test data
      if (iter.hasNext()) {
        throw new IllegalStateException("Attribute value JSON has more than one value mapped.");
      }
      String typeString = rawAttribute.getKey();
      JsonNode value = rawAttribute.getValue();
      switch (typeString) {
        case "S":
          return new AttributeValue().withS(value.asText());
        case "B":
          ByteBuffer b = ByteBuffer.wrap(java.util.Base64.getDecoder().decode(value.asText()));
          return new AttributeValue().withB(b);
        case "N":
          return new AttributeValue().withN(value.asText());
        case "SS":
          final Set<String> stringSet =
              objectMapper.readValue(
                  objectMapper.treeAsTokens(value), new TypeReference<Set<String>>() {});
          return new AttributeValue().withSS(stringSet);
        case "NS":
          final Set<String> numSet =
              objectMapper.readValue(
                  objectMapper.treeAsTokens(value), new TypeReference<Set<String>>() {});
          return new AttributeValue().withNS(numSet);
        default:
          throw new IllegalStateException(
              "DDB JSON type "
                  + typeString
                  + " not implemented for test attribute value deserialization.");
      }
    }
    return null;
  }
}
