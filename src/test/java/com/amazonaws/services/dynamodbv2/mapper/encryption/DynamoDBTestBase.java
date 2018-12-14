package com.amazonaws.services.dynamodbv2.mapper.encryption;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.DescribeTableRequest;
import com.amazonaws.services.dynamodbv2.model.TableDescription;

import java.math.BigDecimal;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.testng.AssertJUnit.assertTrue;
import static org.testng.AssertJUnit.fail;

public class DynamoDBTestBase {
    public AmazonDynamoDB createDefaultClient() {
        return AmazonDynamoDBClientBuilder.standard()
                .withCredentials(getCredentialsProvider()).build();
    }

    public AWSCredentialsProvider getCredentialsProvider() {
        return new DefaultAWSCredentialsProviderChain();
    }

    public void waitForTableToBecomeDeleted(AmazonDynamoDB dynamo, String tableName) {
        System.out.println("Waiting for " + tableName + " to become Deleted...");

        long startTime = System.currentTimeMillis();
        long endTime = startTime + (10 * 60 * 1000);
        while (System.currentTimeMillis() < endTime) {
            try {
                Thread.sleep(1000 * 20);
            } catch (Exception ignored) {
            }
            try {
                DescribeTableRequest request = new DescribeTableRequest().withTableName(tableName);
                TableDescription table = dynamo.describeTable(request).getTable();

                String tableStatus = table.getTableStatus();
                System.out.println("  - current state: " + tableStatus);
            } catch (AmazonServiceException ase) {
                if (ase.getErrorCode().equalsIgnoreCase("ResourceNotFoundException")) {
                    System.out.println("successfully deleted");
                    return;
                }
            }
        }

        throw new RuntimeException("Table " + tableName + " never went deleted");
    }


    protected static <T extends Object> void assertSetsEqual(Collection<T> expected, Collection<T> given) {
        Set<T> givenCopy = new HashSet<T>();
        givenCopy.addAll(given);
        for (T e : expected) {
            if (!givenCopy.remove(e)) {
                fail("Expected element not found: " + e);
            }
        }

        assertTrue("Unexpected elements found: " + givenCopy, givenCopy.isEmpty());
    }

    /**
     * Only valid for whole numbers
     */
    protected static void assertNumericSetsEquals(Set<? extends Number> expected, Collection<String> given) {
        Set<BigDecimal> givenCopy = new HashSet<BigDecimal>();
        for (String s : given) {
            BigDecimal bd = new BigDecimal(s);
            givenCopy.add(bd.setScale(0));
        }

        Set<BigDecimal> expectedCopy = new HashSet<BigDecimal>();
        for (Number n : expected) {
            BigDecimal bd = new BigDecimal(n.toString());
            expectedCopy.add(bd.setScale(0));
        }

        assertSetsEqual(expectedCopy, givenCopy);
    }

    protected static <T extends Object> Set<T> toSet(T... array) {
        Set<T> set = new HashSet<T>();
        for (T t : array) {
            set.add(t);
        }
        return set;
    }

    protected static <T extends Object> Set<T> toSet(Collection<T> collection) {
        Set<T> set = new HashSet<T>();
        for (T t : collection) {
            set.add(t);
        }
        return set;
    }

    protected static byte[] generateByteArray(int length) {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++) {
            bytes[i] = (byte) (i % Byte.MAX_VALUE);
        }
        return bytes;
    }

    protected Map<String, AttributeValue> getMapKey(String attributeName, AttributeValue value) {
        HashMap<String, AttributeValue> map = new HashMap<String, AttributeValue>();
        map.put(attributeName, value);
        return map;
    }
}
