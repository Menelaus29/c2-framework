from evasion.sleep_strat import uniform_sleep, gaussian_sleep

def compute_sleep(base_s: float, jitter_pct: int) -> float:
    # Delegate to uniform_sleep for backward compatibility.
    return uniform_sleep(base_s, jitter_pct)


def gaussian_sleep_compat(base_s: float, jitter_pct: int) -> float:
    # Delegate to gaussian_sleep for backward compatibility.
    return gaussian_sleep(base_s, jitter_pct)