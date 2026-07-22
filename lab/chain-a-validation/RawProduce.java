import org.apache.kafka.clients.producer.*;
import org.apache.kafka.common.serialization.ByteArraySerializer;
import org.apache.kafka.common.serialization.StringSerializer;
import java.nio.file.*;
import java.util.Properties;

public class RawProduce {
    public static void main(String[] args) throws Exception {
        String topic = args[0];
        byte[] payload = Files.readAllBytes(Paths.get(args[1]));
        Properties props = new Properties();
        props.put("bootstrap.servers", "localhost:9092");
        props.put("key.serializer", StringSerializer.class.getName());
        props.put("value.serializer", ByteArraySerializer.class.getName());
        try (KafkaProducer<String, byte[]> producer = new KafkaProducer<>(props)) {
            producer.send(new ProducerRecord<>(topic, "k1", payload)).get();
        }
        System.out.println("Produced " + payload.length + " bytes to topic " + topic);
    }
}
