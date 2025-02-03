# Findings Client

This implementation of `component.Storer` interacts with a findings client via GRPC.

## Configuration

| Environment Variable                | Type   | Required | Default                  | Possible Values          |
|-------------------------------------|--------|----------|--------------------------|--------------------------|
| SMITHY\_REMOTE\_STORE\_FINDINGS\_SERVICE\_ADDR    | string | no       | localhost:50051                        | -                        |
