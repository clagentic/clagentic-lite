# examples/python

Demo project with one planted bug (null-byte injection in `normalize_email`) and one planted secret (`AWS_ACCESS_KEY_ID` in `.env.example`).

Run:

```sh
python3 auth.py user@example.com hunter2
```

Trigger the bug:

```sh
python3 auth.py $'admin@example.com\x00evil' anything
```

See `examples/README.md` for the full demo plot.
