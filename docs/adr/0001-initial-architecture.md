# ADR 0001: Initial Architecture

## Status

Accepted

## Context

We need to build a Proof of Concept (PoC) demonstrating Data-Centric Security (DCS) with Zero Trust principles for a cinema projection tracking system.

## Decision

We will implement a layered architecture with the following components:

### Backend (FastAPI + PostgreSQL)
- **Policy Enforcement Point (PEP)**: Applies access decisions to data
- **Policy Decision Point (PDP)**: Evaluates authorization based on ABAC rules
- **Policy Information Point (PIP)**: Gathers subject and resource attributes
- **Key Management Service (KMS)**: Integrates with HashiCorp Vault Transit for encryption/decryption

### Frontend (React + TypeScript)
- Single Page Application with role-based UI
- JWT-based authentication
- API client with automatic token handling

### Infrastructure
- Nginx as reverse proxy and PEP entry point
- PostgreSQL for data persistence
- HashiCorp Vault for secrets and encryption keys

## Consequences

### Positive
- Clear separation of concerns between PDP, PEP, and PIP
- Field-level access control provides fine-grained security
- Encryption at rest protects sensitive data
- Comprehensive audit logging for compliance

### Negative
- Additional latency from Vault calls for encryption/decryption
- Complexity in managing field classifications
- Cache management required for performance

## References

- XACML/ABAC specifications
- NIST Zero Trust Architecture (SP 800-207)
- HashiCorp Vault Transit Engine documentation
