"""Longer-block robustness cohort using the unchanged primary driver.

Default: 64 requests per block, three repetitions, five policies, honest/mobile
workloads and one/four/eight closed-loop clients at n=42, B=32, p=4.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

import benchmark


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--output', required=True)
    args, _ = parser.parse_known_args()
    if '--attempts' not in sys.argv and not any(x.startswith('--attempts=') for x in sys.argv):
        sys.argv += ['--attempts', '64']
    benchmark.CONFIGS = [c for c in benchmark.CONFIGS
                        if c['n'] == 42 and c['batch'] == 32 and c['slots'] == 4]
    assert sorted(c['clients'] for c in benchmark.CONFIGS) == [1, 4, 8]
    source = Path(__file__).resolve()
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    benchmark.main()
    env_path = Path(args.output) / 'environment.json'
    env = json.loads(env_path.read_text())
    assert hashlib.sha256(source.read_bytes()).hexdigest() == source_hash
    env['source_sha256'][source.name] = source_hash
    env['cohort'] = 'longer finite blocks for response-tail and startup/drain robustness'
    env_path.write_text(json.dumps(env, indent=2) + '\n')


if __name__ == '__main__':
    main()
