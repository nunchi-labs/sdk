# Access-control example

This crate demonstrates how to use the access-control crate as a central RBAC component for other custom modules. 

```text
ApplicationTransaction
|- AccessControl -> AccessControlLedger -> role-management state
`- Counter       -> CounterLedger
                   `- queries AccessControlLedger::has_role for Reset
```

The counter module defines its own transaction format, state, and authorization policy. `Increment` is public,
`Reset` requires `RESETTER_ROLE`. The access-control crate is responsible for the txs that grant and revoke membership.

At genesis, the application calls `initialize` to register the counter's scope and owner. The
application runtime then routes access-control and counter transactions to their respective
ledgers over the same state view.
