package software.amazon.awssdk.enhanced.dynamodb.testing;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;

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
          return AttributeValue.builder().s(value.asText()).build();
        case "B":
          SdkBytes b = SdkBytes.fromByteArray(java.util.Base64.getDecoder().decode(value.asText()));
          return AttributeValue.builder().b(b).build();
        case "N":
          return AttributeValue.builder().n(value.asText()).build();
        case "SS":
          final Set<String> stringSet =
              objectMapper.readValue(
                  objectMapper.treeAsTokens(value), new TypeReference<Set<String>>() {});
          return AttributeValue.builder().ss(stringSet).build();
        case "NS":
          final Set<String> numSet =
              objectMapper.readValue(
                  objectMapper.treeAsTokens(value), new TypeReference<Set<String>>() {});
          return AttributeValue.builder().ns(numSet).build();
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
