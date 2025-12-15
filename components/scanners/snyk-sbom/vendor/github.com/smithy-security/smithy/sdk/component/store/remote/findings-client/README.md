# Findings Client

This implementation of `component.Storer` interacts with a findings client via GRPC.

## Configuration

| Environment Variable                | Type                | Required | Default         | Possible Values          |
|-------------------------------------|---------------------|----------|-----------------|--------------------------|
| SMITHY\_REMOTE\_STORE\_FINDINGS\_SERVICE\_ADDR    | string              | no       | localhost:50051 | -                        |
| SMITHY\_REMOTE\_CLIENT\_MAX\_ATTEMPTS    | int                 | no       | 10              | -                        |
| SMITHY\_REMOTE\_CLIENT\_INITIAL\_BACKOFF\_SECONDS    | duration in seconds | no       | 5s              | -                        |
| SMITHY\_REMOTE\_CLIENT\_MAX\_BACKOFF\_SECONDS    | duration in seconds | no       | 60s             | -                        |
| SMITHY\_REMOTE\_CLIENT\_BACKOFF\_MULTIPLIER    | float               | no       | 1.5             | -                        |
