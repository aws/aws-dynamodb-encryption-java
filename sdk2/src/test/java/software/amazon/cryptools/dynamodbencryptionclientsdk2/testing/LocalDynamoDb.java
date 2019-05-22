/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
package software.amazon.cryptools.dynamodbencryptionclientsdk2.testing;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.URI;

import com.amazonaws.services.dynamodbv2.local.main.ServerRunner;
import com.amazonaws.services.dynamodbv2.local.server.DynamoDBProxyServer;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.CreateTableRequest;
import software.amazon.awssdk.services.dynamodb.model.CreateTableResponse;
import software.amazon.awssdk.services.dynamodb.model.GetItemRequest;
import software.amazon.awssdk.services.dynamodb.model.GetItemResponse;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.PutItemResponse;
import software.amazon.awssdk.services.dynamodb.model.QueryRequest;
import software.amazon.awssdk.services.dynamodb.model.QueryResponse;

/**
 * Wrapper for a local DynamoDb server used in testing. Each instance of this class will find a new port to run on,
 * so multiple instances can be safely run simultaneously. Each instance of this service uses memory as a storage medium
 * and is thus completely ephemeral; no data will be persisted between stops and starts.
 *
 * LocalDynamoDb localDynamoDb = new LocalDynamoDb();
 * localDynamoDb.start();       // Start the service running locally on host
 * DynamoDbClient dynamoDbClient = localDynamoDb.createClient();
 * ...      // Do your testing with the client
 * localDynamoDb.stop();        // Stop the service and free up resources
 *
 * If possible it's recommended to keep a single running instance for all your tests, as it can be slow to teardown
 * and create new servers for every test, but there have been observed problems when dropping tables between tests for
 * this scenario, so it's best to write your tests to be resilient to tables that already have data in them.
 */
public class LocalDynamoDb {
    private DynamoDBProxyServer server;
    private int port;

    /**
     * Start the local DynamoDb service and run in background
     */
    public void start() {
        port = getFreePort();
        String portString = Integer.toString(port);

        try {
            server = createServer(portString);
            server.start();
        } catch (Exception e) {
            throw propagate(e);
        }
    }

    /**
     * Create a standard AWS v2 SDK client pointing to the local DynamoDb instance
     * @return A DynamoDbClient pointing to the local DynamoDb instance
     */
    public DynamoDbClient createClient() {
        String endpoint = String.format("http://localhost:%d", port);
        return DynamoDbClient.builder()
                      .endpointOverride(URI.create(endpoint))
                             // The region is meaningless for local DynamoDb but required for client builder validation
                      .region(Region.US_EAST_1)
                      .credentialsProvider(StaticCredentialsProvider.create(
                          AwsBasicCredentials.create("dummy-key", "dummy-secret")))
                      .build();
    }

    /**
     * If you require a client object that can be mocked or spied using standard mocking frameworks, then you must call
     * this method to create the client instead. Only some methods are supported by this client, but it is easy to add
     * new ones.
     * @return A mockable/spyable DynamoDbClient pointing to the Local DynamoDB service.
     */
    public DynamoDbClient createLimitedWrappedClient() {
        return new WrappedDynamoDbClient(createClient());
    }

    /**
     * Stops the local DynamoDb service and frees up resources it is using.
     */
    public void stop() {
        try {
            server.stop();
        } catch (Exception e) {
            throw propagate(e);
        }
    }

    private DynamoDBProxyServer createServer(String portString) throws Exception {
        return ServerRunner.createServerFromCommandLineArgs(
            new String[]{
                "-inMemory",
                "-port", portString
            });
    }

    private int getFreePort() {
        try {
            ServerSocket socket = new ServerSocket(0);
            int port = socket.getLocalPort();
            socket.close();
            return port;
        } catch (IOException ioe) {
            throw propagate(ioe);
        }
    }

    private static RuntimeException propagate(Exception e) {
        if (e instanceof RuntimeException) {
            throw (RuntimeException)e;
        }
        throw new RuntimeException(e);
    }

    /**
     * This class can wrap any other implementation of a DynamoDbClient. The default implementation of the real
     * DynamoDbClient is a final class, therefore it cannot be easily spied upon unless you first wrap it in a class
     * like this. If there's a method you need it to support, just add it to the wrapper here.
     */
    private static class WrappedDynamoDbClient implements DynamoDbClient {
        private final DynamoDbClient wrappedClient;

        private WrappedDynamoDbClient(DynamoDbClient wrappedClient) {
            this.wrappedClient = wrappedClient;
        }

        @Override
        public String serviceName() {
            return wrappedClient.serviceName();
        }

        @Override
        public void close() {
            wrappedClient.close();
        }

        @Override
        public PutItemResponse putItem(PutItemRequest putItemRequest) {
            return wrappedClient.putItem(putItemRequest);
        }

        @Override
        public GetItemResponse getItem(GetItemRequest getItemRequest) {
            return wrappedClient.getItem(getItemRequest);
        }

        @Override
        public QueryResponse query(QueryRequest queryRequest) {
            return wrappedClient.query(queryRequest);
        }

        @Override
        public CreateTableResponse createTable(CreateTableRequest createTableRequest) {
            return wrappedClient.createTable(createTableRequest);
        }
    }
}
