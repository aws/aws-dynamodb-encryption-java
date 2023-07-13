package com.amazonaws.examples.mapper;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBAttribute;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBFlattened;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBHashKey;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBRangeKey;
import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBTable;

import static com.amazonaws.examples.AwsKmsEncryptedObject.EXAMPLE_TABLE_NAME;
import static com.amazonaws.examples.AwsKmsEncryptedObject.PARTITION_ATTRIBUTE;
import static com.amazonaws.examples.AwsKmsEncryptedObject.SORT_ATTRIBUTE;

@DynamoDBTable(tableName = EXAMPLE_TABLE_NAME)
public class PojoWithFlattened {
  private String partitionAttribute;
  private int sortAttribute;
  private DateRange encryptedRange;
  private DateRangeSigned signedRange;
  private DateRangedDoNotTouch doNotTouchRange;

  @DynamoDBHashKey(attributeName = PARTITION_ATTRIBUTE)
  public String getPartitionAttribute() {
    return partitionAttribute;
  }

  public void setPartitionAttribute(String partitionAttribute) {
    this.partitionAttribute = partitionAttribute;
  }

  @DynamoDBRangeKey(attributeName = SORT_ATTRIBUTE)
  public int getSortAttribute() {
    return sortAttribute;
  }

  public void setSortAttribute(int sortAttribute) {
    this.sortAttribute = sortAttribute;
  }

  @DynamoDBFlattened(attributes={
    @DynamoDBAttribute(mappedBy="start", attributeName="encryptedStart"),
    @DynamoDBAttribute(mappedBy="end", attributeName="encryptedEnd")})
  public DateRange getEncryptedRange() { return encryptedRange; }
  public void setEncryptedRange(DateRange encryptedRange) { this.encryptedRange = encryptedRange; }

  @DynamoDBFlattened(attributes={
    @DynamoDBAttribute(mappedBy="start", attributeName="signedStart"),
    @DynamoDBAttribute(mappedBy="end", attributeName="signedEnd")})
  public DateRangeSigned getSignedRange() { return signedRange; }
  public void setSignedRange(DateRangeSigned signedRange) { this.signedRange = signedRange; }

  @DynamoDBFlattened(attributes={
    @DynamoDBAttribute(mappedBy="start", attributeName="doNotTouchStart"),
    @DynamoDBAttribute(mappedBy="end", attributeName="doNotTouchEnd")})
  public DateRangedDoNotTouch getDoNotTouchRange() { return doNotTouchRange; }
  public void setDoNotTouchRange(DateRangedDoNotTouch doNotTouchRange) { this.doNotTouchRange = doNotTouchRange;}

  @Override
  public String toString() {
    return "PojoWithFlattened [partitionAttribute="
      + partitionAttribute
      + ", sortAttribute="
      + sortAttribute
      + ", encryptedRange="
      + encryptedRange.toString()
      + ", signedRange="
      + signedRange.toString()
      + ", doNotTouchRange="
      + doNotTouchRange.toString()
      + "]";
  }
}
