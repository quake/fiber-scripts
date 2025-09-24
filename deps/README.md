`auth` is a binary built from the `ckb-auth` project. It's used to verify the signature of fiber transactions.
You may rebuild it by running following commands:

```bash
git clone https://github.com/nervosnetwork/ckb-auth.git
cd ckb-auth
git checkout b95f62ce597a5b8678196e2733c0d4dbd07f67f4
git submodule update --init
make all-via-docker
cp build/auth fiber-scripts/deps
```

`simple_udt` is a binary built from the `ckb-production-scripts` project. It's used in unit tests only for udt related functions.
You may rebuild it by running following commands:

```bash
git clone https://github.com/nervosnetwork/ckb-production-scripts.git
cd ckb-production-scripts
git submodule update --init --recursive
make all-via-docker
cp build/simple_udt fiber-scripts/deps
```
