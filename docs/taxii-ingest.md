# TAXII 2.1 Read Adapter

TCE includes a small read-only TAXII 2.1 collection adapter.

The goal is not to become another threat-feed platform. The goal is to allow external STIX intelligence to enter the same provenance and review pipeline used by TCE.

## Pull a collection

    tce taxii-pull \
      https://example.org/taxii2/root/collections/COLLECTION-ID \
      --output taxii-bundle.json

The adapter requests the collection objects endpoint and follows TAXII pagination up to a configurable page limit.

Useful options:

    --added-after 2026-09-01T00:00:00Z
    --limit 100
    --max-pages 20

Authentication can be supplied through environment variables:

    TAXII_TOKEN
    TAXII_USERNAME
    TAXII_PASSWORD

The result is stored locally as a STIX bundle for review or transformation.

## Design boundary

TAXII ingestion does not automatically create hypotheses, scenarios, detections or decisions. It provides intelligence material. Evidence admission remains a separate analytical act.
