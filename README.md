[contributors-shield]: https://img.shields.io/github/contributors/edgefarm/vault-plugin-secrets-nats.svg?style=for-the-badge
[contributors-url]: https://github.com/edgefarm/vault-plugin-secrets-nats/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/edgefarm/vault-plugin-secrets-nats.svg?style=for-the-badge
[forks-url]: https://github.com/edgefarm/vault-plugin-secrets-nats/network/members
[stars-shield]: https://img.shields.io/github/stars/edgefarm/vault-plugin-secrets-nats.svg?style=for-the-badge
[stars-url]: https://github.com/edgefarm/vault-plugin-secrets-nats/stargazers
[issues-shield]: https://img.shields.io/github/issues/edgefarm/vault-plugin-secrets-nats.svg?style=for-the-badge
[issues-url]: https://github.com/edgefarm/vault-plugin-secrets-nats/issues
[license-shield]: https://img.shields.io/github/license/edgefarm/vault-plugin-secrets-nats?style=for-the-badge
[license-url]: https://opensource.org/license/mpl-2-0

[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MPL-2.0 License][license-shield]][license-url]

<!-- PROJECT LOGO -->
<br />
<p align="center">
  <a href="https://github.com/edgefarm/vault-plugin-secrets-nats">
    <img src="https://github.com/edgefarm/edgefarm/raw/beta/.images/EdgefarmLogoWithText.png" alt="Logo" height="112">
  </a>

  <h2 align="center">vault-plugin-secrets-nats</h2>

  <p align="center">
    vault-plugin-secrets-nats extends Hashicorp Vault with a secrets engine for NATS.
  </p>
  <hr />
</p>

# About The Project

`vault-plugin-secrets-nats` is a Hashicorp Vault plugin that extends Vault with a secrets engine for [NATS](https://nats.io) for Nkey/JWT auth. 
It is capable of generating NATS credentials for operators, accounts and users. The generated credentials are stored in Vault and can be revoked at any time.
The plugin is also able to push the generated credentials to a NATS account server. 

A similar project is the [`nsc` tool by NATS](https://github.com/nats-io/nsc) but the `nsc` tool doesn't provide a way to store the generated credentials other than file based. The `nsc` tool is not automated and heavily relies on manual steps.

## Features

- Manage NATS nkey and jwt for operators, accounts and users
- Give access to user creds files
- Push generated credentials to a NATS account server

# Getting Started

The `nats` secrets engine generates NATS credentials dynamically.
The plugin supports several resources, including: operators, accounts, users, NKeys, JWTs and creds, as well as signing keys for operators an accounts.

There is a command structure to create, read update and delete operators, accounts, users and permissions based on entity paths.
Please read the official [NATS documentation](https://docs.nats.io/running-a-nats-service/configuration/securing_nats/auth_intro/jwt) to understand the concepts of operators, accounts and users as well as the authentication process.
A hand full of resources can be defined within the vault plugin:

The resource of type `issue` represent entities that result in generation of nkey and JWTs.

| Entity path                                                   | Description                                                                        | Operations          |
| ------------------------------------------------------------- | ---------------------------------------------------------------------------------- | ------------------- |
| issue/operator                                                | List operator issues                                                               | list                |
| issue/operator/\<operator\>/account                           | List account issues                                                                | list                |
| issue/operator/\<operator\>/account/\<account\>/user          | List user issues within an account                                                 | list                |
| issue/operator/\<operator\>                                   | Manage operator issues. See the `operator` section for more information.           | write, read, delete |
| issue/operator/\<operator\>/account/\<account\>               | Manage account issues. See the `account` section for more information.             | write, read, delete |
| issue/operator/\<operator\>/account/\<account\>/user/\<name\> | Manage user issues within an account. See the `user` section for more information. | write, read, delete |

The resources of type `creds` represent user credentials that can be used to authenticate against a NATS server.

| Entity path                                                 | Description       | Operations          |
| ----------------------------------------------------------- | ----------------- | ------------------- |
| creds/operator/\<operator>account/\<account\>/user          | List user creds   | List                |
| creds/operator/\<operator>account/\<account\>/user/\<user\> | Manage user creds | write, read, update |

Resouces of type `nkey` are either be generated by `issue`s or are imported and referenced by `issue`s during their creation.

| Entity path                                                  | Description                    | Operations          |
| ------------------------------------------------------------ | ------------------------------ | ------------------- |
| nkey/operator                                                | List operator nkeys            | list                |
| nkey/operator/\<operator>/signing                            | List operators' signing nkeys  | list                |
| nkey/operator/\<operator>/account                            | List account nkeys             | list                |
| nkey/operator/\<operator>/account/\<account\>/signing        | List accounts' signing nkeys   | list                |
| nkey/operator/\<operator>/account/\<account\>/user           | List user nkeys                | list                |
| nkey/operator/\<operator>                                    | Manage operator nkey           | write, read, delete |
| nkey/operator/\<operator>/signing/\<key\>                    | Manage operator signing nkeys  | write, read, delete |
| nkey/operator/\<operator>account/\<account\>                 | Manage accounts' nkey          | write, read, delete |
| nkey/operator/\<operator>account/\<account\>/signing/\<key\> | Manage accounts' signing nkeys | write, read, delete |
| nkey/operator/\<operator>account/\<account\>/user/\<user\>   | Manage user nkey               | write, read, delete |

Resource of type 'jwt' are either be generated by `issue`s or are imported and referenced by `issue`s during their creation.

| Entity path                                               | Description           | Operations          |
| --------------------------------------------------------- | --------------------- | ------------------- |
| jwt/operator                                              | List operator JWTs    | list                |
| jwt/operator/\<operator>/account                          | List account JWTs     | list                |
| jwt/operator/\<operator>/account/\<account\>/user         | List user JWTs        | list                |
| jwt/operator/\<operator>                                  | Manage operator JWT   | write, read, delete |
| jwt/operator/\<operator>account/\<account\>               | Manage accounts' JWTs | write, read, delete |
| jwt/operator/\<operator>account/\<account\>/user/\<user\> | Manage user JWT       | write, read, delete |

## ✔️ Prerequisites
ex
TODO

## ⚙️ Configuration

There are arguments that can be passed to the paths for `issue/` (operator, account, user), `creds/`, `jwt/` and `nkey/`.

### Issues

Issues can be created with an imported nkey. If the nkey is not present during the creation of the issue, a new nkey will be generated.
**Note: if you don't provide any claims for an operator, account or user, the plugin will generate a default set of claims. The default claims are set to "you are not allowed to do anything".**

#### **Operator**

| Key               | Type        | Required | Default | Description                                                                                                              |
| ----------------- | ----------- | -------- | ------- | ------------------------------------------------------------------------------------------------------------------------ |
| syncAccountServer | bool        | false    | false   | If set to true, the plugin will push the generated credentials to the configured account server.                         |
| claims            | json string | false    | {}      | Claims to be added to the operator's JWT. See [pkg/claims/operator/v1alpha1/api.go](pkg/claims/operator/v1alpha1/api.go) |

#### **Account**

| Key           | Type        | Required | Default | Description                                                                                                           |
| ------------- | ----------- | -------- | ------- | --------------------------------------------------------------------------------------------------------------------- |
| useSigningKey | string      | false    | ""      | Operator signing key's name, e.g. "opsk1"                                                                             |
| claims        | json string | false    | {}      | Claims to be added to the account's JWT. See [pkg/claims/account/v1alpha1/api.go](pkg/claims/account/v1alpha1/api.go) |

#### **User**

| Key           | Type        | Required | Default | Description                                                                                                  |
| ------------- | ----------- | -------- | ------- | ------------------------------------------------------------------------------------------------------------ |
| useSigningKey | bool        | false    | false   | Account signing key's name, e.g. "opsk1"                                                                     |
| claims        | json string | false    | {}      | Claims to be added to the user's JWT. See [pkg/claims/user/v1alpha1/api.go](pkg/claims/user/v1alpha1/api.go) |

### Nkey

| Key  | Type   | Required | Default | Description                                           |
| ---- | ------ | -------- | ------- | ----------------------------------------------------- |
| seed | string | false    | ""      | Seed to import. If not set, then a new one is created |

### JWT

| Key | Type   | Required | Default | Description                                          |
| --- | ------ | -------- | ------- | ---------------------------------------------------- |
| jwt | string | false    | ""      | JWT to import. If not set, then a new one is created |

### Creds

| Key   | Type   | Required | Default | Description                                                 |
| ----- | ------ | -------- | ------- | ----------------------------------------------------------- |
| creds | string | false    | ""      | Creds file to import. If not set, then a new one is created |

### 📤 System account specific configuration

This section describes the configuration options that are specific to the system account.

The default name of the system account is `sys`. If you want to use a different name, you can set the `systemAccount` configuration option in the `operator`. 
Within the `sys` account the only user that is capable of pushing credentials to the account server is the `default-push` user. 

See the `example/sysaccount` directory for an example configuration of both `sys` account and `default-push` user.

## 🎯 Installation and Setup

In order to use this plugin you need to register it with Vault.
Configure your vault server to have a valid `plugins_directory` configuration. 

**Note: you might want to set `api_addr` to your listening address and `disable_mlock` to `true` in the `vault` configuration to be able to use the plugin.**

### Install from release

Download the latest stable release from the [release](https://github.com/edgefarm/vault-plugin-secrets-nats/releases) page and put it into the `plugins_directory` of your vault server.

To use a vault plugin you need the plugin's sha256 sum. You can download the file `vault-plugin-secrets-nats.sha256` file from the release, obtain it with `sha256sum vault-plugin-secrets-nats` or look within the OCI image at `/etc/vault/vault_plugins_checksums/vault-plugin-secrets-nats.sha256`.

Example how to register the plugin:

```console
SHA256SUM=$(sha256sum vault-plugin-secrets-nats | cut -d' ' -f1)
vault plugin register -sha256 ${SHA256SUM} secret vault-plugin-secrets-nats
vault secrets enable -path=nats-secrets vault-plugin-secrets-nats
```

**Note: you might use the `-tls-skip-verify` flag if you are using a self-signed certificate.**

### Install from OCI image using bank-vaults in Kubernetes

This project provides a custom built `vault` OCI image that includes the `vault-plugin-secrets-nats` plugin. See [here]() for available versions.
The `plugins_directory` must be set to `/etc/vault/vault_plugins` in the `vault` configuration.

This describes the steps to install the plugin using the `bank-vaults` operator. See [here](https://banzaicloud.com/docs/bank-vaults/operator/) for more information.
Define the custom `vault` image in the `Vault` custom resource and configure 

```yaml
apiVersion: "vault.banzaicloud.com/v1alpha1"
kind: "Vault"
metadata:
  name: "myVault"
spec:
  size: 1
  # Use the custom vault image containing the NATS secrets plugin
  image: ghcr.io/edgefarm/vault-plugin-secrets-nats/vault-with-nats-secrets:1.3.2
  config:
    disable_mlock: true
    plugin_directory: "/etc/vault/vault_plugins"
    listener:
      tcp:
        address: "0.0.0.0:8200"
    api_addr: "https://0.0.0.0:8200"
  externalConfig:
    plugins:
    - plugin_name: vault-plugin-secrets-nats
      command: vault-plugin-secrets-nats --tls-skip-verify --ca-cert=/vault/tls/ca.crt
      sha256: 13c753a26991858faf820604c6422c31e49368481a18335c6540ac28a7ce2aac
      type: secret
    secrets:
    - path: nats-secrets
      type: plugin
      plugin_name: vault-plugin-secrets-nats
      description: NATS secrets backend
  # ...
```

See the fule [dev/manifests/vault/vault.yaml](dev/manifests/vault/vault.yaml) for a full example of a `Vault` custom resource that can be used by the `vault-operator`.

## 🧪 Testing

To test the plugin in a production like environment you can spin up a local kind cluster that runs a production `vault` server with the plugin enabled and a NATS server the plugin writes account information to.

**Note: you need to have `kind` and `devspace` installed.**

The first step is to spin up the cluster with everything installed.

```console
# Create the cluster
$ devspace run create-kind-cluster

# Deploy initial stuff like ingress and cert-manager
$ devspace run-pipeline init 

# Deploy the vault-operator and vault instance
$ devspace run-pipeline deploy-vault

# Wait for the vault pods get ready
$ kubectl get pods -n vault 

# Check if the plugin is successfully loaded
$ kubectl port-forward -n vault svc/vault 8200:8200 &
$ PID=$!
$ export VAULT_ADDR=https://127.0.0.1:8200
$ VAULT_TOKEN=$(kubectl get secrets bank-vaults -n vault -o jsonpath='{.data.vault-root}' | base64 -d)
$ echo $VAULT_TOKEN | vault login -
$ vault secrets list
Handling connection for 8200
Path             Type                         Accessor                              Description
----             ----                         --------                              -----------
cubbyhole/       cubbyhole                    cubbyhole_ec217496                    per-token private secret storage
identity/        identity                     identity_9123b895                     identity store
nats-secrets/    vault-plugin-secrets-nats    vault-plugin-secrets-nats_d8584dcc    NATS secrets backend
sys/             system                       system_5bd0e10f                       system endpoints used for control, policy and debugging
$ pkill $PID

# Deploy the NATS server
$ devspace run-pipeline deploy-nats

# Wait for the NATS server to be ready
$ kubectl get pods -n nats
```

Once this is working create a account and a user and act as a third party that uses the creds outside the cluster.

```console
# Create the account and user and get the creds for the user
$ devspace run-pipeline create-custom-nats-account
$ kubectl port-forward -n nats svc/nats 4222:4222 &
$ PID=$!

# Publish and subscribe using the creds previously fetched
$ docker run -it -d --rm --name nats-subscribe --network host -v $(pwd)/.devspace/creds/creds:/creds natsio/nats-box:0.13.4 nats sub -s nats://localhost:4222 --creds /creds foo 
$ docker run --rm -d -it --name nats-publish --network host -v $(pwd)/.devspace/creds/creds:/creds natsio/nats-box:0.13.4 nats pub -s nats://localhost:4222 --creds /creds foo --count 3 "Message {{Count}} @ {{Time}}"

# Log output shows that authenticating with the creds file works for pub and sub
$ docker logs nats-subscribe
14:49:35 Subscribing on foo 
[#1] Received on "foo"
Message 1 @ 2:49PM

[#2] Received on "foo"
Message 2 @ 2:49PM

[#3] Received on "foo"
Message 3 @ 2:49PM

# Cleanup
$ docker kill nats-subscribe
$ pkill $PID

```

# 💡 Example

Read this section to learn how to use `vault-plugin-secrets-nats` by trying out the example. 
See the `example` directory for a full example. The example runs a locally running Vault server and a NATS server.

An operator and a sys account is created. Both are using signing keys. A sys account user called `default-push` is created 
that is used to push the credentials to the NATS account server.
The NATS server is configured to use the generated credentials.
After the NATS server is up and running a new "normal" account and a user is created and pushed to the NATS server.
The user is then able to connect to the NATS server.

Note: please make sure that you have `docker` installed as the example starts a local NATS server using docker.

## 🛠️ Setup

To use the plugin, you must first enable it with Vault. This example mounts the plugin at the path `nats-secrets`:

First run `make` to start a Vault server in dev mode that is pre-configured to use the plugin.

```console
$ make
```

Then, enable the plugin:

```console
$ export VAULT_ADDR='http://127.0.0.1:8200'
$ vault secrets enable -path=nats-secrets vault-plugin-secrets-nats
Success! Enabled the vault-plugin-secrets-nats secrets engine at: nats-secrets/
```

## 🏁 Run the example

```console
$ cd examples
$ ./config.sh
> Creating NATS resources (operator and sysaccount)
Success! Data written to: nats-secrets/issue/operator/myop
Success! Data written to: nats-secrets/issue/operator/myop/account/sys
Success! Data written to: nats-secrets/issue/operator/myop/account/sys/user/default-push
> Generate NATS server config with preloaded operator and sys account settings
> Starting up NATS server
9402e7608bfe8bc391c862eb01f4dbac19e16210a431fb9d84384e009f013a3d
a5bd1e08562382aaf6b40f35203afd479bfa847fddf72a617dbd083446863071
> Creating normal account and user
Success! Data written to: nats-secrets/issue/operator/myop/account/myaccount
Success! Data written to: nats-secrets/issue/operator/myop/account/myaccount/user/user
> Exporting user creds file
> Publishing using user creds file
12:57:09 Published 3 bytes to "foo"
> Cleaning up...
nats
nats
> done.

```
# 🐞 Debugging

The recommended way to debug this plugin is to use write unit tests and debug them as standard go tests.
If you like to debug the plugin in a running Vault instance you can use the following steps:
  1. `make`
  2. `make enable`
  3. Attach to the process using your favorite debugger
  4. Use vault CLI to interact with the plugin
  5. Debug the plugin

# 🤝🏽 Contributing

Code contributions are very much **welcome**.

1. Fork the Project
2. Create your Branch (`git checkout -b AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature")
4. Push to the Branch (`git push origin AmazingFeature`)
5. Open a Pull Request targetting the `beta` branch.

# 🫶 Acknowledgements

Thanks for the NATS developers for providing a really great way of solving many problems with communication.

Also, thanks to the Vault developers for providing a great way of managing secrets and a great plugin system.
