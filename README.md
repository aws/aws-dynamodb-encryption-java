aws-dynamodb-encryption-java
============================

AWS DynamoDB Encryption Client for Java.

The **AWS DynamoDB Encryption Client for Java** supports encryption and signing of your data.

You can either use the AttributeEncryptor with the [DynamoDBMapper][ddbmapper] for transparent protection of all objects serialized through the mapper, or use the DynamoDBEncryptor for tighter control over how the library works. 

[ddbmapper]: http://docs.aws.amazon.com/AWSJavaSDK/latest/javadoc/com/amazonaws/services/dynamodbv2/datamodeling/DynamoDBMapper.html