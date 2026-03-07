import os
import yaml
from dataclasses import dataclass
from common.logger import get_logger

logger = get_logger('transport')

PROFILE_CONFIG_PATH = os.path.join(
    os.path.dirname(__file__), '..', 'evasion', 'profile_config.yaml'
)

_cache: dict[str, 'EvasionProfile'] = {}  # module-level cache to avoid repeated file reads
_raw:   dict = {}                          # cached raw YAML content
VALID_STRATEGIES = ('uniform', 'gaussian')

# Dataclass
@dataclass
class EvasionProfile:
    name:             str
    jitter_pct:       int
    jitter_strategy:  str
    padding_min:      int
    padding_max:      int
    header_level:     int


# Helpers
def _load_yaml() -> dict:
    # Read and parse profile_config.yaml, using cached content if available.
    global _raw
    if _raw:
        return _raw

    path = os.path.abspath(PROFILE_CONFIG_PATH)
    if not os.path.exists(path):
        raise FileNotFoundError(f'profile_config.yaml not found at {path}')

    with open(path, 'r', encoding='utf-8') as f:
        _raw = yaml.safe_load(f)

    return _raw


def _build_profile(name: str, data: dict) -> EvasionProfile:
    strategy = data['strategy']
    padding_min = data['padding_min']
    padding_max = data['padding_max']

    if strategy not in VALID_STRATEGIES:
        raise ValueError(
            f"invalid strategy '{strategy}' in profile '{name}'. "
            f"Valid strategies: {VALID_STRATEGIES}"
        )

    if padding_min > padding_max:
        raise ValueError(
            f"padding_min ({padding_min}) cannot exceed padding_max ({padding_max}) "
            f"in profile '{name}'"
        )

    return EvasionProfile(
        name             = name,
        jitter_pct       = data['jitter_pct'],
        jitter_strategy  = strategy,
        padding_min      = padding_min,
        padding_max      = padding_max,
        header_level     = data['header_level'],
    )


# Public API
def load_profile(name: str) -> EvasionProfile:
    # Load a named profile from profile_config.yaml, using cache if available.
    if name in _cache:
        return _cache[name]

    raw      = _load_yaml()
    profiles = raw.get('profiles', {})

    if name not in profiles:
        available = list(profiles.keys())
        raise ValueError(
            f'profile "{name}" not found in profile_config.yaml. '
            f'Available profiles: {available}'
        )

    profile = _build_profile(name, profiles[name])
    _cache[name] = profile

    logger.info('profile loaded', extra={
        'profile': name,
        'jitter_pct':      profile.jitter_pct,
        'jitter_strategy': profile.jitter_strategy,
        'padding_min':     profile.padding_min,
        'padding_max':     profile.padding_max,
        'header_level':    profile.header_level,
    })

    return profile


def load_active_profile() -> EvasionProfile:
    # Load whichever profile is set as active_profile in profile_config.yaml.
    raw            = _load_yaml()
    active_name    = raw.get('active_profile')

    if not active_name:
        raise ValueError('active_profile field missing from profile_config.yaml')

    return load_profile(active_name)


# Self-test
if __name__ == '__main__':
    print("Running traffic_profile self-test...")

    # Test 1 — load each named profile
    for name in ('baseline', 'low', 'medium', 'high'):
        p = load_profile(name)
        assert p.name == name,          f"FAIL: wrong name for profile '{name}'"
        assert isinstance(p.jitter_pct, int),  f"FAIL: jitter_pct not int in '{name}'"
        assert isinstance(p.padding_min, int), f"FAIL: padding_min not int in '{name}'"
        assert isinstance(p.padding_max, int), f"FAIL: padding_max not int in '{name}'"
        assert p.padding_min <= p.padding_max, \
            f"FAIL: padding_min > padding_max in '{name}'"
        print(f"  [OK] profile '{name}' loaded correctly")

    # Test 2 — verify profile values match spec
    baseline = load_profile('baseline')
    assert baseline.jitter_pct      == 0,         "FAIL: baseline jitter_pct"
    assert baseline.jitter_strategy == 'uniform',  "FAIL: baseline strategy"
    assert baseline.padding_min     == 0,          "FAIL: baseline padding_min"
    assert baseline.padding_max     == 0,          "FAIL: baseline padding_max"
    assert baseline.header_level    == 0,          "FAIL: baseline header_level"
    print("  [OK] baseline values correct")

    high = load_profile('high')
    assert high.jitter_pct      == 40,        "FAIL: high jitter_pct"
    assert high.jitter_strategy == 'gaussian', "FAIL: high strategy"
    assert high.padding_min     == 64,         "FAIL: high padding_min"
    assert high.padding_max     == 256,        "FAIL: high padding_max"
    assert high.header_level    == 3,          "FAIL: high header_level"
    print("  [OK] high values correct")

    # Test 3 — cache works: second load returns same object
    p1 = load_profile('medium')
    p2 = load_profile('medium')
    assert p1 is p2, "FAIL: cache should return the same object"
    print("  [OK] cache returns same object on repeated load")

    # Test 4 — load_active_profile returns medium (per profile_config.yaml)
    active = load_active_profile()
    assert active.name == 'medium', \
        f"FAIL: active_profile should be 'medium', got '{active.name}'"
    print("  [OK] load_active_profile returns 'medium'")

    # Test 5 — unknown profile raises ValueError
    try:
        load_profile('nonexistent')
        print("  FAIL: should have raised ValueError for unknown profile")
    except ValueError as e:
        assert 'nonexistent' in str(e), "FAIL: error message should mention profile name"
        print("  [OK] unknown profile raises ValueError")

    # Test 6 — all profiles have valid strategy values
    for name in ('baseline', 'low', 'medium', 'high'):
        p = load_profile(name)
        assert p.jitter_strategy in ('uniform', 'gaussian'), \
            f"FAIL: invalid strategy '{p.jitter_strategy}' in profile '{name}'"
    print("  [OK] all profiles have valid strategy values")

    print("\nAll traffic_profile self-tests passed.")