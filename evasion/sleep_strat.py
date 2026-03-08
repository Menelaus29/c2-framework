import random
import math
from typing import Callable

MIN_SLEEP_S = 1.0  # floor to prevent zero or negative sleep intervals


def uniform_sleep(base_s: float, jitter_pct: int) -> float:
    # Return a sleep duration using uniform random jitter within +/- jitter_pct of base
    if jitter_pct == 0:
        return float(base_s)
    delta = base_s * (jitter_pct / 100.0)
    return max(MIN_SLEEP_S, random.uniform(base_s - delta, base_s + delta))


def gaussian_sleep(base_s: float, jitter_pct: int) -> float:
    # Return a sleep duration using gaussian jitter with stddev derived from jitter_pct
    if jitter_pct == 0:
        return float(base_s)
    sigma = base_s * (jitter_pct / 100.0)
    return max(MIN_SLEEP_S, random.gauss(base_s, sigma))


def get_sleep_fn(strategy: str) -> Callable:
    # Return the sleep function matching the given strategy name.
    if strategy == 'uniform':
        return uniform_sleep
    if strategy == 'gaussian':
        return gaussian_sleep
    raise ValueError(
        f'unknown jitter strategy "{strategy}". '
        f'Valid strategies: uniform, gaussian'
    )


# Self-test
if __name__ == '__main__':
    import random as _random

    print("Running sleep_strategy self-test...")

    BASE_S = 30.0
    N      = 20

    # Test 1 — baseline profile: jitter_pct=0 always returns exactly base_s
    for fn in (uniform_sleep, gaussian_sleep):
        results = [fn(BASE_S, 0) for _ in range(N)]
        assert all(r == BASE_S for r in results), \
            f"FAIL: {fn.__name__} with jitter_pct=0 should always return base_s"
    print("  [OK] jitter_pct=0 always returns exactly base_s")

    # Test 2 — baseline profile: 20 intervals within 0.05s of BEACON_INTERVAL_S
    _random.seed(42)
    results = [uniform_sleep(BASE_S, 0) for _ in range(N)]
    assert all(abs(r - BASE_S) < 0.05 for r in results), \
        "FAIL: baseline intervals exceed 0.05s tolerance"
    print("  [OK] baseline profile: all 20 intervals within 0.05s of base")

    # Test 3 — high profile: 20 gaussian intervals show clear variance
    _random.seed(None)  # unseed for real randomness
    results = [gaussian_sleep(BASE_S, 40) for _ in range(N)]
    variance = sum((r - BASE_S) ** 2 for r in results) / N
    assert variance > 1.0, \
        f"FAIL: high profile should show clear variance, got variance={variance:.4f}"
    print(f"  [OK] high profile: 20 intervals show clear variance ({variance:.2f})")

    # Test 4 — uniform intervals stay within expected range
    _random.seed(42)
    for _ in range(100):
        r = uniform_sleep(BASE_S, 20)
        assert BASE_S * 0.8 <= r <= BASE_S * 1.2 or r == MIN_SLEEP_S, \
            f"FAIL: uniform result {r:.2f} outside expected range"
    print("  [OK] uniform intervals stay within expected range")

    # Test 5 — all results >= MIN_SLEEP_S
    for fn in (uniform_sleep, gaussian_sleep):
        results = [fn(BASE_S, 40) for _ in range(100)]
        assert all(r >= MIN_SLEEP_S for r in results), \
            f"FAIL: {fn.__name__} returned value below MIN_SLEEP_S"
    print("  [OK] all results >= MIN_SLEEP_S")

    # Test 6 — get_sleep_fn returns correct functions
    assert get_sleep_fn('uniform')  is uniform_sleep,  "FAIL: wrong fn for uniform"
    assert get_sleep_fn('gaussian') is gaussian_sleep, "FAIL: wrong fn for gaussian"
    print("  [OK] get_sleep_fn returns correct functions")

    # Test 7 — get_sleep_fn raises ValueError for unknown strategy
    try:
        get_sleep_fn('random_walk')
        print("  FAIL: should raise ValueError for unknown strategy")
    except ValueError as e:
        assert 'random_walk' in str(e), "FAIL: error should mention strategy name"
        print("  [OK] get_sleep_fn raises ValueError for unknown strategy")

    print("\nAll sleep_strategy self-tests passed.")