# examples/node

Demo project with one planted bug (null-byte injection in `normalizeEmail`) and one planted secret (`AWS_ACCESS_KEY_ID` in `.env.example`).

Run:

```sh
node auth.js user@example.com hunter2
```

See `examples/README.md` for the full demo plot.
