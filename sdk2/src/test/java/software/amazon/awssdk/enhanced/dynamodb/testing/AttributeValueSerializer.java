package software.amazon.awssdk.enhanced.dynamodb.testing;

import com.amazonaws.util.Base64;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import java.io.IOException;
import java.nio.ByteBuffer;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;


public class AttributeValueSerializer extends JsonSerializer<AttributeValue> {
  @Override
  public void serialize(AttributeValue value, JsonGenerator jgen, SerializerProvider provider)
      throws IOException {
    if (value != null) {
      jgen.writeStartObject();
      if (value.s() != null) {
        jgen.writeStringField("S", value.s());
      } else if (value.b() != null) {
        ByteBuffer valueBytes = value.b().asByteBuffer();
        byte[] arr = new byte[valueBytes.remaining()];
        valueBytes.get(arr);
        jgen.writeStringField("B", Base64.encodeAsString(arr));
      } else if (value.n() != null) {
        jgen.writeStringField("N", value.n());
      } else if (value.hasSs()) {
        jgen.writeFieldName("SS");
        jgen.writeStartArray();
        for (String s : value.ss()) {
          jgen.writeString(s);
        }
        jgen.writeEndArray();
      } else if (value.hasNs()) {
        jgen.writeFieldName("NS");
        jgen.writeStartArray();
        for (String num : value.ns()) {
          jgen.writeString(num);
        }
        jgen.writeEndArray();
      } else {
        throw new IllegalStateException(
            "AttributeValue has no value or type not implemented for serialization.");
      }
      jgen.writeEndObject();
    }
  }
}
