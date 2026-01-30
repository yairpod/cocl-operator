# Examples

The examples directories contains how you can run and attest a [KubeVirt](https://github.com/kubevirt/kubevirt) VM against the Trusted Execution Clusters operator.

## How to use KubeVirt example

Before provisioning the KubeVirt VM, a secret with the ignition configuration needs to be created. You can use the helper script:
```console
examples/create-ignition-secret.sh examples/ignition-coreos.json coreos-ignition-secret
```

The `ignition-coreos.json` contains some basic configuration for the attestation server and the merge request for the clevis pin.

Then, the KubeVirt VM can be deployed:
```console
kubectl apply -f examples/vm-coreos-ign.yaml 
```

The example deploys an image build from the [investigations](https://github.com/trusted-execution-clusters/investigations) repository.
