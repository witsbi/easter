# RETIRED / HISTORICAL -- do not run.
#
# Predates requester_identity_id becoming a required keyword-only
# argument on Kernel.transition(). Will raise TypeError if run.
# NaN/Infinity rejection is now covered, against the current API,
# by state_1_invariants.py (State red-team regression suite).

from kernel import Kernel, KernelError

kernel = Kernel()

for name, value in [
    ("nan", float("nan")),
    ("infinity", float("inf")),
]:
    try:
        kernel.transition(
            from_state_id="state:genesis",
            authority_grant_id="grant:genesis-root",
            new_state_payload={
                "value": value,
            },
            transition_payload={
                "test": name,
            },
        )

        print(f"{name}: UNEXPECTEDLY ACCEPTED")

    except Exception as exc:
        print(f"{name}: rejected")
        print(f"  {type(exc).__name__}: {exc}")
