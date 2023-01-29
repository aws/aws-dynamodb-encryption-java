# Client-side Encryption for Amazon DynamoDB

The **[Amazon DynamoDB][ddb] Client-side Encryption in Java** supports encryption and signing of your data when stored in Amazon DynamoDB.

For more advanced use cases where tighter control over the encryption and signing process is necessary, the low-level [DynamoDBEncryptor][ddbencryptor] can be used directly.

[Security issue notifications](./CONTRIBUTING.md#security-issue-notifications)

See [Support Policy](./SUPPORT_POLICY.rst) for for details on the current support status of all major versions of this library.

There are two versions of this library dependent on your version of the AWS SDK:

* [SDK v1](./sdk1/README.md)
* [SDK v2](./sdk2/README.md)

[ddb]: http://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Introduction.html
[ddbencryptor]: sdk1/src/main/java/com/amazonaws/services/dynamodbv2/datamodeling/encryption/DynamoDBEncryptor.java
