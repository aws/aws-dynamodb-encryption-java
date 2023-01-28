package software.amazon.awssdk.enhanced.dynamodb.encryption.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import software.amazon.awssdk.enhanced.dynamodb.internal.tags.EncryptionExtensionTags;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.BeanTableSchemaAttributeTag;

@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@BeanTableSchemaAttributeTag(EncryptionExtensionTags.class)
public @interface Signed {
}
