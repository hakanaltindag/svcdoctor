# ADR 0005: Kafka first

## Decision

v0.1 is limited to Kafka and PostgreSQL. Kafka is implemented first, and PostgreSQL feature work starts only after the Kafka acceptance criteria are met.

Kafka advertised-topology failures are a strong early test of the evidence DAG and probe/adapter separation.
