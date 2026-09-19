from kernel import Kernel, KernelError

kernel = Kernel()

try:
    kernel.transition(
        requester_identity_id="identity:nathan",
        from_state_id="state:genesis",
        authority_grant_id="grant:does-not-exist",
        new_state_payload={
            "message": "This state must never exist"
        },
        transition_payload={
            "reason": "Kernel rejection test"
        },
    )
except KernelError as exc:
    print(f"Expected rejection: {exc}")
