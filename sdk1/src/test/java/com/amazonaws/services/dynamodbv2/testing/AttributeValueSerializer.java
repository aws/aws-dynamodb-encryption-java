package com.amazonaws.services.dynamodbv2.testing;

import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.util.Base64;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

import java.io.IOException;
import java.nio.ByteBuffer;

public class AttributeValueSerializer extends JsonSerializer<AttributeValue> {
    @Override
    public void serialize(AttributeValue value, JsonGenerator jgen,
                          SerializerProvider provider) throws IOException {
        if (value != null) {
            jgen.writeStartObject();
            if (value.getS() != null) {
                jgen.writeStringField("S", value.getS());
            } else if (value.getB() != null) {
                ByteBuffer valueBytes = value.getB();
                byte[] arr = new byte[valueBytes.remaining()];
                valueBytes.get(arr);
                jgen.writeStringField("B", Base64.encodeAsString(arr));
            } else if (value.getN() != null) {
                jgen.writeStringField("N", value.getN());
            } else if (value.getSS() != null) {
                jgen.writeFieldName("SS");
                jgen.writeStartArray();
                for (String s : value.getSS()) {
                    jgen.writeString(s);
                }
                jgen.writeEndArray();
            } else if (value.getNS() != null) {
                jgen.writeFieldName("NS");
                jgen.writeStartArray();
                for (String num : value.getNS()) {
                    jgen.writeString(num);
                }
                jgen.writeEndArray();
            } else {
                throw new IllegalStateException("AttributeValue has no value or type not implemented for serialization.");
            }
            jgen.writeEndObject();
        }
    }
}
