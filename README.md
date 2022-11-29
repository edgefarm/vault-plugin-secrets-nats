# Vault Plugin Secrets Nats

The `nats` secrets engine generates Nats credentials dynamically.
The plugin supports several resources, including:

There is a command structure to create, read update and delete operators, accounts, users and permissions.

| Path                             | Resource                                                                                                                                 | Operations                |
|----------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|---------------------------|
| cmd/operator                     | Manages the operator. If you need several operators, mount the plugin several times.<br>See the `operator` section for more information. | write, read, delete       |
| cmd/operator/account             | Manages accounts. See the `account` section for more information.                                                                        | write, list, read, delete |
| cmd/operator/account/<name>/user | Manages users within accounts. See the `user` section for more information.                                                              | write, list, read, delete |

## Usage



## License
