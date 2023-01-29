package software.amazon.awssdk.enhanced.dynamodb;

import java.io.File;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public interface DynamoDbLocalTest {

    LocalDynamoDb localDynamoDb = new LocalDynamoDb();

    @BeforeAll
    default void startDynamoDb() {
        localDynamoDb.start();
    }

    @AfterAll
    default void stopDynamoDb() { localDynamoDb.stop(); }

    default DynamoDbClient dynamoDbClient() { return localDynamoDb.createClient(); }

}
