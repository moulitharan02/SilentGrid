"""
Synthetic network traffic generator - creates realistic traffic patterns
"""
import random
import json
import sys
import os
from datetime import datetime
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from src.config.config import KAFKA_BOOTSTRAP_SERVERS, KAFKA_TOPIC_RAW
from kafka import KafkaProducer

# IPs and ports
INTERNAL_IPS = ["192.168.1.100", "192.168.1.101", "192.168.1.102", "192.168.1.50"]
EXTERNAL_IPS = ["8.8.8.8", "1.1.1.1", "208.67.222.222", "5.6.7.8", "10.11.12.13"]
PORTS = [80, 443, 22, 21, 3306, 5432, 8080, 8443, 53, 25]
PROTOCOLS = ["tcp", "udp"]
LABELS = ["BENIGN", "DDoS", "PortScan", "BruteForce"]

def generate_traffic(count: int = 100, rate: int = 10):
    """Generate synthetic network traffic and send to Kafka"""
    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )
    
    sent = 0
    delay = 1.0 / rate if rate > 0 else 0
    
    for i in range(count):
        # Generate realistic traffic patterns
        if random.random() < 0.1:  # 10% anomalies
            src_ip = random.choice(EXTERNAL_IPS)
            dst_ip = random.choice(INTERNAL_IPS)
            label = random.choice(["DDoS", "PortScan", "BruteForce"])
            duration = random.uniform(0.1, 100)
            bytes_sent = random.randint(1000000, 10000000)  # Large traffic
        else:  # Normal traffic
            src_ip = random.choice(INTERNAL_IPS)
            dst_ip = random.choice(EXTERNAL_IPS) if random.random() > 0.5 else random.choice(INTERNAL_IPS)
            label = "BENIGN"
            duration = random.uniform(0.001, 60)
            bytes_sent = random.randint(100, 100000)
        
        # Create record with fields expected by the feature engine
        resp_bytes = random.randint(100, bytes_sent)
        orig_pkts = random.randint(1, 10000)
        resp_pkts = random.randint(1, 10000)
        
        record = {
            "@timestamp": datetime.utcnow().isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": random.choice(PORTS),
            "dst_port": random.choice(PORTS),
            "protocol": random.choice(PROTOCOLS),
            "duration": duration,
            "orig_bytes": bytes_sent,           # Feature engine expects "orig_bytes"
            "resp_bytes": resp_bytes,           # Feature engine expects "resp_bytes"
            "orig_pkts": orig_pkts,             # Feature engine expects "orig_pkts"
            "resp_pkts": resp_pkts,             # Feature engine expects "resp_pkts"
            "orig_ip_bytes": bytes_sent + 20,
            "resp_ip_bytes": resp_bytes + 20,
            "label": label,                     # For reference/testing only
            "risk_score": random.randint(0, 100) if label != "BENIGN" else random.randint(0, 30),
        }
        
        producer.send(KAFKA_TOPIC_RAW, record)
        sent += 1
        
        if sent % 10 == 0:
            print(f"  ✓ Sent {sent} traffic records...")
        
        if delay:
            time.sleep(delay)
    
    producer.flush()
    print(f"\n✓ Generated {sent} synthetic network traffic records to Kafka")
    producer.close()

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--count", type=int, default=500, help="Number of records to generate")
    p.add_argument("--rate", type=int, default=20, help="Records per second")
    p.add_argument("--continuous", action="store_true", help="Generate continuously")
    args = p.parse_args()
    
    if args.continuous:
        print("Generating traffic continuously (Ctrl+C to stop)...")
        try:
            while True:
                generate_traffic(count=args.count, rate=args.rate)
                print("  Waiting 30 seconds before next batch...")
                time.sleep(30)
        except KeyboardInterrupt:
            print("\nStopped.")
    else:
        generate_traffic(count=args.count, rate=args.rate)
