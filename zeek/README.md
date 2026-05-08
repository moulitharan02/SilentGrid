# Zeek Integration — Phase 1

## Overview

This module converts Zeek's TSV-format `conn.log` into JSON records
and publishes them to the Kafka `raw-traffic` topic for downstream processing.

## Prerequisites

- Zeek installed and capturing traffic (or a pre-recorded log available)
- Kafka broker running on `localhost:9092` (or as configured in `.env`)
- Python dependencies installed: `pip install -r requirements.txt`

## Usage

### One-shot (process existing log)
```bash
python zeek/zeek_to_json.py --log /var/log/zeek/current/conn.log
```

### Stream to Kafka
```bash
python zeek/zeek_to_json.py \
  --log /var/log/zeek/current/conn.log \
  --kafka \
  --topic raw-traffic \
  --bootstrap localhost:9092
```

### Real-time tail (follow mode)
```bash
python zeek/zeek_to_json.py \
  --log /var/log/zeek/current/conn.log \
  --follow \
  --kafka
```

## Output Fields (conn.log)

| Field         | Description                          |
|---------------|--------------------------------------|
| `id.orig_h`   | Source IP                            |
| `id.orig_p`   | Source port                          |
| `id.resp_h`   | Destination IP                       |
| `id.resp_p`   | Destination port                     |
| `proto`       | Protocol (tcp / udp / icmp)          |
| `duration`    | Connection duration (seconds)        |
| `orig_bytes`  | Bytes sent by originator             |
| `resp_bytes`  | Bytes sent by responder              |
| `orig_pkts`   | Packets sent by originator           |
| `resp_pkts`   | Packets sent by responder            |

## Next Steps

Once records arrive in Kafka, the main pipeline (`src/main.py`) picks them up,
extracts features, runs ML detection, and fires alerts automatically.
