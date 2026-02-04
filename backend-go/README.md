# backend-go

Second backend service for the Cinema DCS PoC.

This service is designed to coexist with the current Python backend during migration.

## Current scope

- Bootstrapped Go service layout (`cmd`, `internal`, `proto`, `gen`).
- gRPC + HTTP server skeleton.
- Versioned protobuf contracts for:
  - DCS policy evaluation
  - DCS crypto/KMS operations
  - Cinema domain operations

## Local commands

```bash
make run
make test
make proto-lint
make proto-gen
```

Default ports:

- HTTP: `:8001`
- gRPC: `:50051`
