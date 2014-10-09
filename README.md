# Client-side Encryption for Amazon DynamoDB

The **[Amazon DynamoDB][ddb] Client-side Encryption in Java** supports encryption and signing of your data when stored in Amazon DynamoDB.

A typical use of this library is when you are using [DynamoDBMapper][ddbmapper], where transparent protection of all objects serialized through the mapper can be enabled via configuring an [AttributeEncryptor][attrencryptor].

For more advanced use cases where tighter control over the encryption and signing process is necessary, the low-level [DynamoDBEncryptor][ddbencryptor] can be used directly.

## Getting Started

Suppose you have created a DynamoDB table "MixedObject", and want to store some Book objects with the security requirements that the attributes Title and Authors need to be treated as sensitive information.  This is how the Book class may look like:

```
@DynamoDBTable(tableName="MixedObject")
public class Book {
    private Integer id;
    private String title;
    private String ISBN;
    private Set<String> bookAuthors;
    private String someProp;
 
    // Not encrypted because it is a hash key    
    @DynamoDBHashKey(attributeName="Id")  
    public Integer getId() { return id;}
    public void setId(Integer id) {this.id = id;}
 
    // Encrypted by default
    @DynamoDBAttribute(attributeName="Title")  
    public String getTitle() {return title; }
    public void setTitle(String title) { this.title = title; }
 
    // Specifically not encrypted
    @DoNotEncrypt
    @DynamoDBAttribute(attributeName="ISBN")  
    public String getISBN() { return ISBN; }
    public void setISBN(String ISBN) { this.ISBN = ISBN; }
 
    // Encrypted by default
    @DynamoDBAttribute(attributeName = "Authors")
    public Set<String> getBookAuthors() { return bookAuthors; }
    public void setBookAuthors(Set<String> bookAuthors) { this.bookAuthors = bookAuthors; }
 
    // Not stored in DynamoDB at all
    @DynamoDBIgnore
    public String getSomeProp() { return someProp;}
    public void setSomeProp(String someProp) {this.someProp = someProp;}
}
```

As usual, you may save and retrieve a Book object to and from Amazon DynamoDB via DynamoDBMapper.  For example,

```
    AmazonDynamoDBClient client = new AmazonDynamoDBClient(...);
    DynamoDBMapper mapper = new DynamoDBMapper(client);
    Book book = new Book();
    book.setId(123);
    book.setTitle("Secret Book Title ");
    // ... etc.

    // Saves the book unencrypted to DynamoDB
    mapper.save(book);

    // Loads the book from DynamoDB
    Book bookToLoad = new Book();
    bookToLoad.setId(123);
    Book bookToLoad = mapper.load(bookToLoad);

```

To enable transparent encryption and signing, simply configure DynamoDBMapper with the necessary encryption material provider.  For example:

```
        AmazonDynamoDBClient client = new AmazonDynamoDBClient(awsTestCredentials());
        SecretKey cek = ...;
        SecretKey macKey =  ...;
        EncryptionMaterialsProvider provider = new SymmetricStaticProvider(cek, macKey);
        mapper = new DynamoDBMapper(client, config, new AttributeEncryptor(provider));
        ...

        // Saves the book both encrypted and signed to DynamoDB
        mapper.save(book);

        // Loads the book both decrypted and with signature verified from DynamoDB
        ...
        Book bookToLoad = mapper.load(bookToLoad);

```

Note that by default all attributes except the primary keys are both encrypted and signed for maximum security.  To selectively disable encryption, the annotation @DoNotEncrypt can be used as shown in the Book class above.  To selectively disable both encryption and signing, the annotation @DoNotTouch can be used.

There is a variety of existing EncryptionMaterialsProvider implemenations that you can use to provide the encryption material, including the use of Java keystore.  Alternatively, you can also plug in your own for your specific use cases.

## Supported Algorithms

For data encryption, the encryption algorithm is user specified, but the encryption mode is always CBC with PKCS5Padding.  Typically, this means AES keys.

For signing, the user provided key can be either symmetric or asymmetric.  For asymetric signing, currently the only supported algorithm is "SHA256withRSA", and user would need to provide the necessary PrivateKey.  For symmetric signing, the algorithm used depends on the user supplied signing key.  A typical algorithm for a symmetric signing key is "HmacSHA256".

## FAQ

1. Is the content-encrypting key and signing key stored along side with the data in Amazon DynamoDB ?
  * No.  The content-encrypting key and signing key are supplied by the user via the EncryptionMaterialsProvider, which also needs to return the corresponding "matrial descriptions" that subsequently be used by the EncryptionMaterialsProvider to identify the corresponding encryption material.  Only the material description is stored along side with the data in Amazon DynamoDB.

2. How is the IV generated and where is it stored ?
  * For each attribute that needs to be encrypted, a unique IV is randomly generated, and get stored along side with the binary representation of the attribute value.

3. How many bits are used for the random IV ?
  * The size used for the random IV is the as the block size of the block cipher used for content encryption, which therefore depends on the specific algorithm of the secret key provided by the user (via EncryptionMaterialsProvider).  Typically this means AES and which therefore 128 bits.

4. How is the key length for the content encrypting key ?
  * This depends on the specific secret key provided by the user (via EncryptionMaterialsProvider).  The typical key length of AES key is 128 bits or 256 bits.

## Known Limitations

Currently the new data types in AmmazonDynamoDB including Map, List, Boolean, and NULL are not yet supported by this library.  This means the crypto layer would fail fast upon detecting the use of the new data types.  We expect to support the new types soon in upcoming releases.

[attrencryptor]: https://github.com/awslabs/aws-dynamodb-encryption-java/blob/master/src/main/java/com/amazonaws/services/dynamodbv2/datamodeling/AttributeEncryptor.java
[ddb]: http://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Introduction.html
[ddbencryptor]: https://github.com/awslabs/aws-dynamodb-encryption-java/blob/master/src/main/java/com/amazonaws/services/dynamodbv2/datamodeling/encryption/DynamoDBEncryptor.java
[ddbmapper]: http://docs.aws.amazon.com/AWSJavaSDK/latest/javadoc/com/amazonaws/services/dynamodbv2/datamodeling/DynamoDBMapper.html
