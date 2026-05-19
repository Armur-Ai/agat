//! Dockerized dynamic analysis.
//!
//! Phase 9 (optional). Will drive bollard against locked-down Alpine
//! and Wine container images: network-isolated, resource-capped,
//! syscall-traced, file/registry diffed, pcap-captured. Strictly
//! opt-in via `agat sandbox <sample-id> --execute`.
