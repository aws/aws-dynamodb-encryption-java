aws-dynamodb-encryption-java
============================

Amazon DynamoDB Encryption Client for Java.

The **[Amazon DynamoDB][ddb] Encryption Client for Java** supports encryption and signing of your data.

You can either use the [AttributeEncryptor][attrencryptor] with the [DynamoDBMapper][ddbmapper] for transparent protection of all objects serialized through the mapper, or use the [DynamoDBEncryptor][ddbencryptor] for tighter control over how the library works. 

[attrencryptor]: https://github.com/awslabs/aws-dynamodb-encryption-java/blob/master/src/main/java/com/amazonaws/services/dynamodbv2/datamodeling/AttributeEncryptor.java
[ddb]: http://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Introduction.html
[ddbencryptor]: https://github.com/awslabs/aws-dynamodb-encryption-java/blob/master/src/main/java/com/amazonaws/services/dynamodbv2/datamodeling/encryption/DynamoDBEncryptor.java
[ddbmapper]: http://docs.aws.amazon.com/AWSJavaSDK/latest/javadoc/com/amazonaws/services/dynamodbv2/datamodeling/DynamoDBMapper.html
