"""
streaming/producer.py
Producteur Kafka optionnel des journaux d'accès TP7.
"""
import json
import os

from dotenv import load_dotenv

from streaming.simulate_from_csv import stream_events

load_dotenv()


def get_producer():
    """Retourne un KafkaProducer configuré depuis .env."""
    from kafka import KafkaProducer
    bootstrap_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    return KafkaProducer(
        bootstrap_servers=bootstrap_servers,
        value_serializer=lambda v: json.dumps(v, ensure_ascii=False).encode("utf-8"),
    )


def publish_access_logs(csv_path: str = "datasets/access_logs.csv", topic: str = "access_logs") -> int:
    """Publie les événements CSV dans Kafka sans bloquer si Kafka est indisponible."""
    topic = os.getenv("KAFKA_TOPIC", topic)
    try:
        producer = get_producer()
    except Exception as exc:
        print(f"[STREAMING] Kafka indisponible, utilisez simulate_from_csv.py : {exc}")
        return 0

    count = 0
    try:
        for event in stream_events(csv_path):
            producer.send(topic, value=event)
            count += 1
            if count % 100 == 0:
                print(f"[STREAMING] {count} événements publiés sur {topic}.")
        producer.flush()
    except Exception as exc:
        print(f"[STREAMING] Publication Kafka interrompue sans faire planter l'appelant : {exc}")
    finally:
        producer.close()
    return count


if __name__ == "__main__":
    total = publish_access_logs()
    print(f"[STREAMING] Publication terminée : {total} événements.")
