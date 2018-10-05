# Custom permissions:

`app1` is the DP
`app2` is the DC

Currently 4 custom permissions required for smart contract interaction (may be consolidated into 1 "unif" in future)

`modschema`, `modperms`, `modreq`, `modrsakey`

Each permission can be locked into a specific set of smart contract actions. E.g. `modreq` can only be used
for `initreq` and `updatereq` smart contract actions

First, a key-pair is created for each custom permission, e.g. assuming `app1`:

```
cleos create key --to-console
Private key: 5JUzHmN8WdFUmVyXyHv1NxfT8T2aCNYudvC5RQX8KpF7S8WBbwq
Public key: EOS6aj3Bc71sVMeAzAU7BQXcSv8zcSjUecXVW2YecD5dnFJs9ERPJ
```

Private key is then imported into app1's wallet:

`cleos wallet import --name app1 --private-key 5JUzHmN8WdFUmVyXyHv1NxfT8T2aCNYudvC5RQX8KpF7S8WBbwq`

The permission is created on the account, e.g. for `modreq`:

`cleos set account permission [account_name] [perm_name] '{"threshold":1,"keys":[{"key":"YOUR_PUB_KEY","weight":1}]}' "[parent_permission]" -p [account_name]@active`

`cleos set account permission app1 modreq '{"threshold":1,"keys":[{"key":"EOS6aj3Bc71sVMeAzAU7BQXcSv8zcSjUecXVW2YecD5dnFJs9ERPJ","weight":1}]}' "active" -p app1@active`

Finally, account permission is associated/locked to specific smart contract actions, using:

`cleos set action permission [account_name] [smart_contract] [contract_action] [custom_permission] -p [account_name]@active`

`cleos set action permission app1 app1 initreq modreq -p app1@active`

link can be removed by replaceing `[custom_permission]` with `NULL`

Note: Some permissions that require interacting with other smart contracts will also need applying. E.g. `app2` is
a DC for `app1`. `app1` needs to update `app2`'s smart contract with data hash, so will need to run first:

`cleos set action permission app1 app2 updatereq modreq -p app1@active`

which allows `app1` to use its `modreq` permission in `app2`'s contract.

## Actions within smart contract

When a DC initialises a data request, the `initreq` action in the DC's smart contract calls the `initperm`
action in the DP'c smart contract. Two permissions need setting up: `modreq` needs to be applied
to the DP's smart contract action `initperm`:

`cleos set action permission app2 app1 initperm modreq -p app2@active`

Additionally, since it's the smart contract executing the call to `app1->initperm`, the 
built in `eosio.code` permission needs adding to `app2`'s `modreq` permission (using the same public key
as used for the `modreq` permission)

`cleos set account permission app2 modreq '{"threshold": 1,"keys": [{"key": "EOS6aj3Bc71sVMeAzAU7BQXcSv8zcSjUecXVW2YecD5dnFJs9ERPJ","weight": 1}],"accounts": [{"permission":{"actor":"app2","permission":"eosio.code"},"weight":1}]}' -p app2@active`

