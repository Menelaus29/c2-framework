import random


def compute_sleep(base_s: float | int, jitter_pct: float | int) -> float:
    # Return base_s with uniform random jitter applied, minimum 1.0 second.
    if base_s <= 0:
        raise ValueError("base_s must be > 0")
    if jitter_pct < 0:
        raise ValueError("jitter_pct must be >= 0")
    
    result = base_s * random.uniform(
        1 - jitter_pct / 100,
        1 + jitter_pct / 100,
    )
    return max(1.0, result)


def gaussian_sleep(base_s: float | int, jitter_pct: float | int) -> float:
    # Return base_s with gaussian jitter applied, minimum 1.0 second.
    if base_s <= 0:
        raise ValueError("base_s must be > 0")
    if jitter_pct < 0:
        raise ValueError("jitter_pct must be >= 0")
    
    sigma  = base_s * jitter_pct / 100
    result = random.gauss(base_s, sigma)
    return max(1.0, result)


# Self-test
if __name__ == '__main__':
    BASE    = 30
    JITTER  = 20
    SAMPLES = 20
    SEED    = 42  # fixed seed for reproducibility verification

    print(f"compute_sleep  — base={BASE}s, jitter={JITTER}% ({SAMPLES} samples):")
    random.seed(SEED)
    uniform_samples = [compute_sleep(BASE, JITTER) for _ in range(SAMPLES)]
    for i, s in enumerate(uniform_samples, 1):
        bar = '#' * int(s / 2)
        print(f"  {i:>2}. {s:6.2f}s  {bar}")

    print()
    print(f"gaussian_sleep — base={BASE}s, jitter={JITTER}% ({SAMPLES} samples):")
    random.seed(SEED)
    gauss_samples = [gaussian_sleep(BASE, JITTER) for _ in range(SAMPLES)]
    for i, s in enumerate(gauss_samples, 1):
        bar = '#' * int(s / 2)
        print(f"  {i:>2}. {s:6.2f}s  {bar}")

    print()

    # Determinism check — same seed must produce identical sequences
    random.seed(SEED)
    run1 = [compute_sleep(BASE, JITTER) for _ in range(SAMPLES)]
    random.seed(SEED)
    run2 = [compute_sleep(BASE, JITTER) for _ in range(SAMPLES)]
    assert run1 == run2, "FAIL: compute_sleep is not deterministic with same seed"
    print("  [OK] compute_sleep is deterministic when seeded")

    random.seed(SEED)
    run3 = [gaussian_sleep(BASE, JITTER) for _ in range(SAMPLES)]
    random.seed(SEED)
    run4 = [gaussian_sleep(BASE, JITTER) for _ in range(SAMPLES)]
    assert run3 == run4, "FAIL: gaussian_sleep is not deterministic with same seed"
    print("  [OK] gaussian_sleep is deterministic when seeded")

    # Floor check — no sample should be below 1.0 second
    assert all(s >= 1.0 for s in uniform_samples), \
        "FAIL: compute_sleep produced a value below 1.0s"
    assert all(s >= 1.0 for s in gauss_samples), \
        "FAIL: gaussian_sleep produced a value below 1.0s"
    print("  [OK] all samples >= 1.0 second")

    # Range check — uniform samples must stay within expected bounds
    lo = BASE * (1 - JITTER / 100)  # 24.0s at base=30, jitter=20
    hi = BASE * (1 + JITTER / 100)  # 36.0s at base=30, jitter=20
    assert all(lo <= s <= hi for s in uniform_samples), \
        f"FAIL: compute_sleep produced a value outside [{lo}, {hi}]"
    print(f"  [OK] uniform samples stay within [{lo:.1f}s, {hi:.1f}s]")

    # Jitter_pct=0 must always return exactly base_s
    for _ in range(10):
        assert compute_sleep(BASE, 0) == float(BASE), \
            "FAIL: compute_sleep with jitter_pct=0 should return base_s exactly"
        assert gaussian_sleep(BASE, 0) == float(BASE), \
            "FAIL: gaussian_sleep with jitter_pct=0 should return base_s exactly"
    print("  [OK] jitter_pct=0 always returns base_s exactly")

    print("\nAll jitter self-tests passed.")