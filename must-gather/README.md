# Gathering information about your cluster

The `gather` script collects information about your cluster for debugging.
Redact information as appropriate when sending this information with production secrets.

```sh
# Optionally set $COLLECTION_PATH to collect to a directory other than .
$ ./gather
```

This script is also compatible with OpenShift's `must-gather`:
```sh
$ oc adm must-gather --image=quay.io/trusted-execution-clusters/must-gather
```
