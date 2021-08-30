# Changelog
## 2.0.2 -- 2021-08-30
Fixes:
* NPE if reading record without a signature fields
([#152](https://github.com/aws/aws-dynamodb-encryption-java/pull/152))
* Add Formatter
([#146](https://github.com/aws/aws-dynamodb-encryption-java/pull/146))
* Update user agent string to correctly reflect version
([#141](https://github.com/aws/aws-dynamodb-encryption-java/pull/141))
* Moving Javadoc to webroot
([#140](https://github.com/aws/aws-dynamodb-encryption-java/pull/140))
* Data model migration doc breadcrumb.
([#139](https://github.com/aws/aws-dynamodb-encryption-java/pull/139))

Maintenance:
* chore: bump aws-java-sdk-bom from 1.11.460 to 1.12.51
 ([#154](https://github.com/aws/aws-dynamodb-encryption-java/pull/154))
* chore: Add support policy
([#149](https://github.com/aws/aws-dynamodb-encryption-java/pull/149))
* CI: Create release builds that validate on multiple JDKs
([#148](https://github.com/aws/aws-dynamodb-encryption-java/pull/148))
* chore: Add exmaple for MRKs
([#145](https://github.com/aws/aws-dynamodb-encryption-java/pull/145))
* chore: Add repo-sync actions
([#143](https://github.com/aws/aws-dynamodb-encryption-java/pull/143))
* chore: Add issue template
([#142](https://github.com/aws/aws-dynamodb-encryption-java/pull/142))

## 2.0.1 -- 2021-02-12
### Bugfix
Fixes released jar files to ensure JDK 8 compatibility.

## 2.0.0 -- 2021-02-04
Removes MostRecentProvider.
MostRecentProvider is replaced by CachingMostRecentProvider as of 1.15.0.

## 1.15.0 -- 2021-02-04
Adds the CachingMostRecentProvider and deprecates MostRecentProvider.

Time-based key reauthorization logic in MostRecentProvider did not re-authorize the use of the key
after key usage permissions were changed at the key provider
(for example AWS Key Management Service).
This created the potential for keys to be used in the DynamoDB Encryption Client after permissions
to do so were revoked.

CachingMostRecentProvider replaces MostRecentProvider and provides a cache entry TTL to reauthorize
the key with the key provider.

MostRecentProvider is now deprecated, and is removed in 2.0.0.
See https://docs.aws.amazon.com/dynamodb-encryption-client/latest/devguide/most-recent-provider.html#mrp-versions for more details.

1.15.0 also fixes interoperability issues between the Python and Java implementations of DynamoDB Encryption Client.

## 1.14.1 -- 2019-10-14
Fixes `com.amazonaws:aws-dynamodb-encryption-java` so that it may be consumed
in mavenCentral.
## 1.14.0 -- 2019-10-14
Use 1.14.1 instead. This release relies on a dependency that isn't
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
* Upgrade Bouncy Castle from 1.61 to 1.65 #119



## 1.13.0 -- 2018-12-10

### Minor Changes

* Add support for overriding the EncryptionContext in DynamoDBEncryptor #60

### Documentation

* Update examples to use PUT instead of Clobber #60
* Document the minimum supported JDK version as JDK8 #57
