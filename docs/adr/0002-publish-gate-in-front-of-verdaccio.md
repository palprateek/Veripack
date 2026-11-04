# Publish gate in front of Verdaccio

Status: accepted; amended 2026-11-04 by the V1 design contract

Verdaccio provides the npm protocol, uplinks, private package storage, and auth plugins, but its publish path makes a release available immediately. We will put a gateway in front of Verdaccio: the gateway is the only public endpoint, owns auth, pending state, and audit orchestration, stores pending tarballs in S3, and replays approved publishes to Verdaccio over a private network with rotating, least-privilege service identities. Pending releases never reach Verdaccio, so they cannot be installed by accident. Verdaccio network isolation and its service credentials are hard root invariants, not configurable policy.

## Considered options

- **Custom Verdaccio plugin**: deeper integration, but couples the gate to Verdaccio internals and makes the pending state harder to audit.
- **Registry from scratch**: full control, but months of protocol, auth, and storage work before the audit engine can be tested.
