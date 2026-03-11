import pytest
import random
from evasion.sleep_strat import (
    uniform_sleep,
    gaussian_sleep,
    get_sleep_fn,
    MIN_SLEEP_S,
)


class TestUniformSleep:

    def test_zero_jitter_returns_exact_base(self):
        # jitter_pct=0 is the baseline profile — must be fully deterministic
        for base in (1.0, 10.0, 30.0, 60.0):
            assert uniform_sleep(base, 0) == float(base), (
                f"uniform_sleep({base}, 0) should return exactly {float(base)}"
            )

    def test_zero_jitter_is_deterministic_across_calls(self):
        # 50 calls with jitter_pct=0 must all return the same value
        results = [uniform_sleep(30.0, 0) for _ in range(50)]
        assert len(set(results)) == 1, (
            "uniform_sleep with jitter_pct=0 returned different values across calls"
        )

    def test_returns_float(self):
        assert isinstance(uniform_sleep(30.0, 20), float)

    def test_result_never_below_min_sleep(self):
        # floor must hold across all jitter levels and base values
        for base in (1.0, 2.0, 30.0):
            for pct in (0, 10, 20, 40, 50):
                for _ in range(50):
                    result = uniform_sleep(base, pct)
                    assert result >= MIN_SLEEP_S, (
                        f"uniform_sleep({base}, {pct}) returned {result} "
                        f"which is below MIN_SLEEP_S={MIN_SLEEP_S}"
                    )

    def test_result_within_expected_range(self):
        # with 20% jitter on 30s base, results must stay in [24.0, 36.0]
        # unless clamped to MIN_SLEEP_S
        base, pct = 30.0, 20
        delta = base * (pct / 100.0)
        for _ in range(100):
            result = uniform_sleep(base, pct)
            assert (base - delta) <= result <= (base + delta) or result == MIN_SLEEP_S, (
                f"uniform_sleep({base}, {pct}) returned {result} "
                f"outside expected range [{base - delta}, {base + delta}]"
            )

    def test_nonzero_jitter_produces_variation(self):
        # 50 calls must not all return the same value
        results = {uniform_sleep(30.0, 20) for _ in range(50)}
        assert len(results) > 1, (
            "uniform_sleep with jitter_pct=20 returned identical values "
            "across 50 calls — randomness is broken"
        )

    def test_min_sleep_clamp_triggers_on_small_base(self):
        # base=0.5 with any jitter must always be clamped to MIN_SLEEP_S
        for _ in range(30):
            result = uniform_sleep(0.5, 50)
            assert result >= MIN_SLEEP_S

    def test_high_jitter_still_respects_floor(self):
        # 50% jitter on a 1s base can produce values near 0 — floor must catch them
        for _ in range(100):
            result = uniform_sleep(1.0, 50)
            assert result >= MIN_SLEEP_S


class TestGaussianSleep:

    def test_zero_jitter_returns_exact_base(self):
        for base in (1.0, 10.0, 30.0, 60.0):
            assert gaussian_sleep(base, 0) == float(base)

    def test_zero_jitter_is_deterministic_across_calls(self):
        results = [gaussian_sleep(30.0, 0) for _ in range(50)]
        assert len(set(results)) == 1

    def test_returns_float(self):
        assert isinstance(gaussian_sleep(30.0, 20), float)

    def test_result_never_below_min_sleep(self):
        # gaussian can produce large negative deviations — floor is critical
        for base in (1.0, 2.0, 30.0):
            for pct in (0, 10, 20, 40):
                for _ in range(100):
                    result = gaussian_sleep(base, pct)
                    assert result >= MIN_SLEEP_S, (
                        f"gaussian_sleep({base}, {pct}) returned {result} "
                        f"below MIN_SLEEP_S={MIN_SLEEP_S}"
                    )

    def test_nonzero_jitter_produces_variation(self):
        results = {gaussian_sleep(30.0, 20) for _ in range(50)}
        assert len(results) > 1, (
            "gaussian_sleep with jitter_pct=20 returned identical values "
            "across 50 calls"
        )

    def test_high_jitter_shows_clear_variance(self):
        # 40% jitter on 30s base should produce measurable spread
        results = [gaussian_sleep(30.0, 40) for _ in range(50)]
        variance = sum((r - 30.0) ** 2 for r in results) / len(results)
        assert variance > 1.0, (
            f"gaussian_sleep(30.0, 40) showed variance={variance:.4f} "
            f"which is too low — jitter may not be applied"
        )

    def test_min_sleep_clamp_triggers_on_small_base(self):
        for _ in range(50):
            result = gaussian_sleep(0.5, 50)
            assert result >= MIN_SLEEP_S

    def test_seeded_zero_jitter_is_unaffected_by_seed(self):
        # jitter_pct=0 must bypass random entirely — seed changes nothing
        random.seed(0)
        r1 = gaussian_sleep(30.0, 0)
        random.seed(999)
        r2 = gaussian_sleep(30.0, 0)
        assert r1 == r2 == 30.0


class TestGetSleepFn:

    def test_uniform_returns_uniform_sleep_function(self):
        fn = get_sleep_fn('uniform')
        assert fn is uniform_sleep

    def test_gaussian_returns_gaussian_sleep_function(self):
        fn = get_sleep_fn('gaussian')
        assert fn is gaussian_sleep

    def test_returned_uniform_fn_is_callable(self):
        fn = get_sleep_fn('uniform')
        result = fn(30.0, 20)
        assert isinstance(result, float)

    def test_returned_gaussian_fn_is_callable(self):
        fn = get_sleep_fn('gaussian')
        result = fn(30.0, 20)
        assert isinstance(result, float)

    def test_unknown_strategy_raises_value_error(self):
        with pytest.raises(ValueError):
            get_sleep_fn('random_walk')

    def test_error_message_contains_strategy_name(self):
        # the error message must name the bad strategy so it's debuggable
        with pytest.raises(ValueError, match='random_walk'):
            get_sleep_fn('random_walk')

    def test_empty_string_raises_value_error(self):
        with pytest.raises(ValueError):
            get_sleep_fn('')

    def test_case_sensitive_raises_value_error(self):
        # 'Uniform' and 'GAUSSIAN' are not valid — strategy names are lowercase only
        with pytest.raises(ValueError):
            get_sleep_fn('Uniform')
        with pytest.raises(ValueError):
            get_sleep_fn('GAUSSIAN')