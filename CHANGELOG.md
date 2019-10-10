# Changelog
## 1.14.0 -- 2019-10-10

### Minor Changes
* Add ExtraDataSupplier to Metastore #76
* Add support for overriding KMS requests in DirectKMSMaterialProvider #76
* Allow DoNotEncrypt and DoNotTouch to be used a a field level #95
* Allow overriding KMS encryption context #102

### Maintanence
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
