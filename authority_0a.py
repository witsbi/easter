from kernel import Kernel

kernel = Kernel()

result = kernel.transition(
    from_state_id="state:genesis",
    authority_grant_id="grant:genesis-root",
    new_state_payload={
        "genesis": 1,
        "version": "0.1",
        "identities": [
            "identity:nathan",
            "identity:clawde",
        ],
    },
    transition_payload={
        "experiment": "AUTHORITY-0A",
        "reason": "Nathan/root authorizes creation of a second persistent identity",
    },
    new_identities=[
        {
            "identity_id": "identity:clawde",
            "payload": {
                "name": "Clawde",
                "role": "persistent_identity",
            },
        }
    ],
)

print(result)
print(kernel.get_state(result["state_id"]))
print(kernel.get_grant("grant:genesis-root"))
