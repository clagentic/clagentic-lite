# examples/go

Demo project with one planted bug (null-byte injection in `NormalizeEmail`) and one planted secret (`AWS_ACCESS_KEY_ID` in `.env.example`).

Run:

```sh
go run auth.go user@example.com hunter2
```

See `examples/README.md` for the full demo plot.
