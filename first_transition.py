from kernel import Kernel

kernel = Kernel()

result = kernel.transition(
    requester_identity_id="identity:nathan",
    from_state_id="state:genesis",
    authority_grant_id="grant:genesis-root",
    new_state_payload={
        "message": "First authoritative post-genesis state"
    },
    transition_payload={
        "reason": "Kernel v0.1 first transition test"
    },
)

print(result)
