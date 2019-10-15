# Changelog
## 1.15.0
The same as 1.14.1. Fixes `com.amazonaws:aws-dynamodb-encryption-java` so that
it may be consumed in mavenCentral.
## 1.14.1 -- 2019-10-14
Fixes `com.amazonaws:aws-dynamodb-encryption-java` so that it may be consumed
in mavenCentral.
## 1.14.0 -- 2019-10-14
Skip 1.14.0 and use 1.15.0 instead. This release relies on a dependency that isn't
available in mavenCentral.

### Minor Changes
* Add ExtraDataSupplier to Metastore #76
* Add support for overriding KMS requests in DirectKMSMaterialProvider #76
* Allow DoNotEncrypt and DoNotTouch to be used at a field level #95
* Allow overriding KMS encryption context #102

### Maintenance
* Migrate from JUnit to TestNG
* Added JaCoCo for code coverage
* Replace Base64 implementation with Java 8's #82
* Added checkstyle



## 1.13.0 -- 2018-12-10

### Minor Changes

* Add support for overriding the EncryptionContext in DynamoDBEncryptor #60

### Documentation

* Update examples to use PUT instead of Clobber #60
* Document the minimum supported JDK version as JDK8 #57
