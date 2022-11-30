[contributors-shield]: https://img.shields.io/github/contributors/edgefarm/vault-plugin-secrets-nats.svg?style=for-the-badge
[contributors-url]: https://github.com/edgefarm/vault-plugin-secrets-nats/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/edgefarm/vault-plugin-secrets-nats.svg?style=for-the-badge
[forks-url]: https://github.com/edgefarm/vault-plugin-secrets-nats/network/members
[stars-shield]: https://img.shields.io/github/stars/edgefarm/vault-plugin-secrets-nats.svg?style=for-the-badge
[stars-url]: https://github.com/edgefarm/vault-plugin-secrets-nats/stargazers
[issues-shield]: https://img.shields.io/github/issues/edgefarm/vault-plugin-secrets-nats.svg?style=for-the-badge
[issues-url]: https://github.com/edgefarm/vault-plugin-secrets-nats/issues
[license-shield]: https://img.shields.io/github/license/edgefarm/vault-plugin-secrets-nats?logo=mit&style=for-the-badge
[license-url]: https://opensource.org/licenses/MIT

[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]

<!-- PROJECT LOGO -->
<br />
<p align="center">
  <a href="https://github.com/edgefarm/vault-plugin-secrets-nats">
    <img src="https://github.com/edgefarm/edgefarm/raw/beta/.images/EdgefarmLogoWithText.png" alt="Logo" height="112">
  </a>

  <h2 align="center">vault-plugin-secrets-nats</h2>

  <p align="center">
    vault-plugin-secrets-nats extends Hashicorp Vault with a secrets engine for Nats.
  </p>
  <hr />
</p>

# About The Project

`vault-plugin-secrets-nats` is a Hashicorp Vault plugin that extends Vault with a secrets engine for Nats.
It is capable of generating Nats credentials for operators, accounts and users. The generated credentials are stored in Vault and can be revoked at any time.
The plugin also also able to push the generated credentials to a Nats account server.

## Features

- Manage Nats credentials for operators, accounts and users
- Push generated credentials to a Nats account server

# Getting Started

The `nats` secrets engine generates Nats credentials dynamically.
The plugin supports several resources, including: operators, accounts, users, NKeys and JWTs.

There is a command structure to create, read update and delete operators, accounts, users and permissions.

| Command path                     | Resource                                                                                                                                 | Operations                |
|----------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|---------------------------|
| cmd/operator                     | Manages the operator. See the `operator` section for more information. | write, read, delete       |
| cmd/operator/account             | Manages accounts. See the `account` section for more information.                                                                        | write, list, read, delete |
| cmd/operator/account/\<name\>/user | Manages users within accounts. See the `user` section for more information.                                                              | write, list, read, delete |

## ✔️ Prerequisites

TODO

## ⚙️ Configuration

TODO

## 🎯 Installation

TODO

## 🧪 Testing

TODO

# 💡 Usage

Read this section to learn how to use `vault-plugin-secrets-nats`.

## Setup

TODO: rework to describe the setup of the plugin in an prod environment

To use the plugin, you must first enable it with Vault:

```console
$ vault secrets enable -path=nats-secrets vault-plugin-secrets-nats
Success! Enabled the vault-plugin-secrets-nats secrets engine at: nats-secrets/
```


## Managing Operator

The `cmd/operator` command manages the operator. If you need several operators, mount the plugin several times. You can specify multiple operator signing keys with the `operator-signing-keys` parameter. See the `Operator Key` section for more information to create operator NKeys.

### Creating/Updating operator

Create or update an operator:

```console
vault write [flags] nats-secrets/cmd/operator [optional parameters]
```

**Valid parameters:**

| Parameter                | Default    | Required | Example                             | Description                                                                                                                                                  |
|--------------------------|------------|----------|-------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| nkey_id                  | "operator" | false    | "mynkey"                            | The nkey id of the operator. If not provided the name of the operator is used                                                                                |
| operator_signing_keys    | ""         | false    | "sk1,sk2"                           | Comma seperated list of additional signing keys for the operator. These NKey IDs must be created before the operator is created (see <br>`nkey`<br> section) |
| strict_signing_key_usage | false      | false    | true                                | if true, all resources signed by the operator must also use signing keys.                                                                                    |
| account_server_url       | ""         | false    | "https://accounts.example.com:1234" | The natst account server url to push changes to. If not set, pushing is disabled.                                                                            |
| system_account           | "SYS"      | false    | "mysys"                             | The default name of the sys account that gets created.                                                                                                       |

### Reading operator

To read the operator:
```console
vault read nats-secrets/cmd/operator
```

### Examples

```console
$ vault write nats-secrets/nkey/operator/sk2 name=sk2
Success! Data written to: nats-secrets/nkey/operator/sk2

$ vault write nats-secrets/nkey/operator/sk1 name=sk1
Success! Data written to: nats-secrets/nkey/operator/sk1

$ vault write nats-secrets/cmd/operator nkey_id=op operator_signing_keys=sk1,sk2 strict_signing_key_usage=true
Success! Data written to: nats-secrets/cmd/operator

$ vault read nats-secrets/cmd/operator
Key         Value
---         -----
claims      map[ClaimsData:map[Audience: Expires:0 ID:YYY5E2E4NLCMHZ34YES7WWGV2EWTY3QYVVZO32MV76UISZOFYQIQ
 IssuedAt:1669760749 Issuer:ODQWQVRJ6TGR2732QJRLHJBLZL6LITH2CTGBPWABF6RCNVHR6K7AGDTX Name: NotBefore:0
 Subject:ODQWQVRJ6TGR2732QJRLHJBLZL6LITH2CTGBPWABF6RCNVHR6K7AGDTX] Operator:map[AccountServerURL:
 AssertServerVersion: GenericFields:map[Tags:<nil> Type:operator Version:2] OperatorServiceURLs:<nil>
 SigningKeys:[OARNBR4TXXRM5UEOD62IKTHG4ELI2IL3JE44XPU6DD5KPWM7HQIHJVO4
 OD3ZXQZTWBDYO7IVV3UVF7CTXHMZLMNI2TJRSIHWFLH3HV3KZGPYYZ4Q] StrictSigningKeyUsage:true SystemAccount:SYS]]
name        operator
nkey_id     op
token_id    op
```

## Managing accounts

The `cmd/operator/account` command manages accounts. You can create multiple accounts for an operator. Note that the operator has to be created before you can create accounts.

### Creating/updating accounts

Create or update an account.

**Syntax:**

```console
vault write nats-secrets/cmd/operator/account/<name> [optional parameters]
```

**Valid parameters:**

| Parameter                                | Default        | Required | Example   | Description                                                                                             |
|------------------------------------------|----------------|----------|-----------|---------------------------------------------------------------------------------------------------------|
| nkey_id                                  | account's name | false    | "myAccount" | Create or use existing NKey with this id                                                                |
| operator_signing_key                     | ""             | false    | "sk1"       | Explicitly specified operator signing key to sign the account                                           |
| account_signing_keys                     | ""             | false    | "ask1,ask2" | Comma seperated list of other account NKeys IDs that can be used to sign on behalf of the accounts NKey |
| limits_nats_subs                         | -1             | false    | 10        | Max number of subscriptions (-1 is unlimited)                                                           |
| limits_nats_data                         | -1             | false    | 10        | Max number of bytes (-1 is unlimited)                                                                   |
| limits_nats_payload                      | -1             | false    | 10        | Max message payload (-1 is unlimited)                                                                   |
| limits_account_imports                   | -1             | false    | 5         | Max number of imports (-1 is unlimited)                                                                 |
| limits_account_exports                   | -1             | false    | 5         | Max number of exports (-1 is unlimited)                                                                 |
| limits_account_wildcards                 | true           | false    | false     | Wildcards allowed in exports                                                                            |
| limits_account_conn                      | -1             | false    | 5         | Max number of active connections (-1 is unlimited)                                                      |
| limits_account_leaf                      | -1             | false    | 1         | Max number of active leaf node connections (-1 is unlimited)                                            |
| limits_jetstream_mem_storage             | -1             | false    | 1024      | Max number of bytes for memory storage (-1 is unlimited / 0 disabled)                                   |
| limits_jetstream_disk_storage            | -1             | false    | 1024      | Max number of bytes for disk storage (-1 is unlimited / 0 disabled)                                     |
| limits_jetstream_streams                 | -1             | false    | 5         | Max number of streams (-1 is unlimited)                                                                 |
| limits_jetstream_consumer                | -1             | false    | 2         | Max number of consumers (-1 is unlimited)                                                               |
| limits_jetstream_max_ack_pending         | -1             | false    | 5         | Max ack pending of a Stream (-1 is unlimited)                                                           |
| limits_jetstream_memory_max_stream_bytes | 0              | false    | 104857600 | Max bytes a memory backed stream can have. (0 means disabled/unlimited)                                 |
| limits_jetstream_disk_max_stream_bytes   | 0              | false    | 104857600 | Max bytes a disk backed stream can have. (0 means disabled/unlimited)                                   |
| limits_jetstream_max_bytes_required      | false          | false    | true      | Max bytes required by all Streams                                                                       |


### Listing all accounts

**Syntax:**

```bash
vault list nats-secrets/cmd/operator/account
```

### Reading a specific account

Read specific account.

**Syntax:**

```bash
vault read nats-secrets/cmd/operator/account/<name>
```

### Examples

```console
$ vault write nats-secrets/cmd/operator/account/myAccount nkey_id=myAccountKey
Success! Data written to: nats-secrets/cmd/operator/myAccount

$ vault list nats-secrets/cmd/operator/account
Keys
----
SYS
myAccount

$ vault read nats-secrets/cmd/operator/account/myAccount
vault read nats-secrets/cmd/operator/account/myAccount
Key         Value
---         -----
claims      map[Account:map[DefaultPermissions:map[Pub:map[Allow:<nil> Deny:<nil>] Resp:<nil> Sub:map[Allow:<nil> Deny:<nil>]] Exports:<nil> GenericFields:map[Tags:<nil> Type:account Version:2] Imports:<nil> Info:map[Description: InfoURL:] Limits:map[AccountLimits:map[Conn:-1 DisallowBearer:false Exports:-1 Imports:-1 LeafNodeConn:-1 WildcardExports:true] JetStreamLimits:map[Consumer:-1 DiskMaxStreamBytes:0 DiskStorage:-1 MaxAckPending:-1 MaxBytesRequired:false MemoryMaxStreamBytes:0 MemoryStorage:-1 Streams:-1] JetStreamTieredLimits:<nil> NatsLimits:map[Data:-1 Payload:-1 Subs:-1]] Mappings:<nil> Revocations:<nil> SigningKeys:<nil>] ClaimsData:map[Audience: Expires:0 ID:ZOXFI45CMULNZFOLPU5ZZGLT4B53GPLZFN2C5QHTI6IUABHUTD6A IssuedAt:1669797750 Issuer:OBQHIV2NFEU3WMM76PX2ZDJR6X2ALPWRVWBL42KTZA3KGBCBOF4CKPNQ Name:myAccount NotBefore:0 Subject:ABO2OY27CKBCJG7I7MYFYL5QKZM4OT5TIFZY7FGRZO6BC2XZ3P2YBEQP]]
name        myAccount
nkey_id     myAccountKey
token_id    myAccountKey
```

**Examples**:

```console
$ vault write nats-secrets/nkey/operator/sk2 name=sk2
Success! Data written to: nats-secrets/nkey/operator/sk2
$ vault write nats-secrets/nkey/operator/sk1 name=sk1
Success! Data written to: nats-secrets/nkey/operator/sk1
$ vault write nats-secrets/cmd/operator nkey_id=op operator_signing_keys=sk1,sk2 strict_signing_key_usage=true
Success! Data written to: nats-secrets/cmd/operator

$ vault read nats-secrets/cmd/operator
Key         Value
---         -----
claims      map[ClaimsData:map[Audience: Expires:0 ID:YYY5E2E4NLCMHZ34YES7WWGV2EWTY3QYVVZO32MV76UISZOFYQIQ
 IssuedAt:1669760749 Issuer:ODQWQVRJ6TGR2732QJRLHJBLZL6LITH2CTGBPWABF6RCNVHR6K7AGDTX Name: NotBefore:0
 Subject:ODQWQVRJ6TGR2732QJRLHJBLZL6LITH2CTGBPWABF6RCNVHR6K7AGDTX] Operator:map[AccountServerURL:
 AssertServerVersion: GenericFields:map[Tags:<nil> Type:operator Version:2] OperatorServiceURLs:<nil>
 SigningKeys:[OARNBR4TXXRM5UEOD62IKTHG4ELI2IL3JE44XPU6DD5KPWM7HQIHJVO4
 OD3ZXQZTWBDYO7IVV3UVF7CTXHMZLMNI2TJRSIHWFLH3HV3KZGPYYZ4Q] StrictSigningKeyUsage:true SystemAccount:SYS]]
name        operator
nkey_id     op
token_id    op
```

## Managing Users

TODO

## Managing NKeys

By creating an operator or account an corresponding NKey is created by default. However, if you need additional signing keys for the operator or accounts, you can create them using this path.

The `nkey/<category>` path manages NKeys for different categories. Possible categories are:

  * `operator` - NKeys for the operator
  * `account` - NKeys for accounts
  * `user` - NKeys for users


### Creating/Updating a specific NKey for a category

**Syntax:**

```bash
vault write [flags] nats-secrets/nkey/<category>/<name> [name=<name>]
```

**Valid parameters:**

| Parameter | Default | Required | Example                                                                          | Description              |
|-----------|---------|----------|----------------------------------------------------------------------------------|--------------------------|
| seed      | ""      | false    | U0FBREU1N0RTWjdVUTRLU0ZVUVlQUFk1R1pIQzRCSlBCRExKS1ZKNEFPWlJDNzNEWkFWRDdBRVZOQQ== | NKey seed to be imported |

### Listing all NKeys for a category

Syntax:

```bash
vault list nats-secrets/nkey/<category>
```

### Reading a specific NKey for a category

Syntax:

```bash
vault read nats-secrets/nkey/<category>/<name>
```

### Examples

```console
# Create an NKey for the operator
$ vault write nats-secrets/nkey/operator/osk1 name=osk1
Success! Data written to: nats-secrets/nkey/operator/osk1

# Create an NKey for the account
$ vault write nats-secrets/nkey/account/ask1 name=ask1
Success! Data written to: nats-secrets/nkey/account/ask1

# Create an NKey for the user
$ vault write nats-secrets/nkey/user/uk1 name=u1
Success! Data written to: nats-secrets/nkey/user/uk1

# Listing operator NKeys
$ vault list nats-secrets/nkey/operator
Keys
----
op
osk1

# Read operator NKey for specific account
$ vault read nats-secrets/nkey/operator/osk1
Key            Value
---            -----
name           osk1
private_key    UENISUdDRjJIMjU2TVNDN0FQMzZMS0dTQk9SVkdGVVRYNTJIS0lIUFkySFNFN08zM0EzQlZXNldKSlNISE02NkI3SUJPRjZMQlZPSldJS1JBWFdTUjdPUUg3VFo3RVJOSEFTU1RYV1dVWDJB
public_key     ODN5MSTEOOZ54D6QC4L4WDK4TMQVCBPNFD65AP7HT6JC2OBFFHPNM5IZ
seed           U09BSTVBWUlYSTdMWFpTSUw0QjdQWk5JMklGMkdVWVdTTzdYSTVKQTU3REk2SVQ1M1BNRE1HU00ySQ==
```

## Managing JWTs

# 📖 Examples

TODO

# 🐞 Debugging

TODO

# 📜 History

TODO

# 🤝🏽 Contributing

Code contributions are very much **welcome**.

1. Fork the Project
2. Create your Branch (`git checkout -b AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature")
4. Push to the Branch (`git push origin AmazingFeature`)
5. Open a Pull Request targetting the `beta` branch.

# 🫶 Acknowledgements

TODO