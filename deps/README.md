`auth` is a binary built from the `ckb-auth` project. It's used to verify the signature of fiber transactions.
You may rebuild it by running following commands:

```bash
git clone https://github.com/nervosnetwork/ckb-auth.git
cd ckb-auth
git checkout 68c93a3a07a462eb4e42a293fe94d759ed1b21ee
git submodule update --init
make all-via-docker
cp build/auth ckb-pcn-scripts/deps
```

`simple_udt` is a binary built from the `ckb-production-scripts` project. It's used in unit tests only for udt related functions.
You may rebuild it by running following commands:

```bash
git clone https://github.com/nervosnetwork/ckb-production-scripts.git
cd ckb-production-scripts
git submodule update --init --recursive
make all-via-docker
cp build/simple_udt ckb-pcn-scripts/deps
```
