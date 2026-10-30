"""Sweep detector thresholds on labelled TRAIN/VALIDATION lab captures. Read-only.

Run: python -m datasets.tune_lab GRID.json LABELS.json [...] [--max-false-alerts 1.0] [--out sweep.json]

GRID.json maps whitelisted thresholds to the values to try, e.g.
  {"tls_indicators.MIN_CLIENT_POPULATION": [3, 5, 8], "slow_http.MIN_SLOW_CONNECTIONS": [30, 50, 100]}
Every combination (at most MAX_COMBINATIONS) is scored with the lab harness. Combinations
are ranked by mean episode recall over the threat classes present in the labels, subject to
a cap on benign false alerts per 1,000 benign events; ties go to fewer false alerts, then
higher alert precision. Captures labelled split "test" are refused: the test split is scored
once, at the end, with the chosen settings, never swept. Nothing is written to the runtime:
the report lists the winning values for you to apply deliberately.
"""
import argparse
import itertools
import json
import sys
from contextlib import contextmanager
from pathlib import Path

from datasets import evaluate_lab
from datasets.lab_labels import LabelError, load
from detection import rule_thresholds, tls_indicators
from features import slow_http, slow_read

MAX_COMBINATIONS = 200
MODULES = {'tls_indicators': tls_indicators, 'slow_http': slow_http, 'slow_read': slow_read,
           'rule_thresholds': rule_thresholds}
TUNABLE = {
    'tls_indicators': ('MIN_SESSION_PACKETS', 'MAX_SIZE_CV', 'MAX_IAT_CV', 'MAX_MEAN_BYTES',
                       'MAX_FINGERPRINT_CLIENTS', 'MIN_CLIENT_POPULATION'),
    'slow_http': ('MIN_SLOW_CONNECTIONS', 'MIN_AGE_S', 'MAX_CLIENT_RATE_BPS'),
    'slow_read': ('MIN_SLOW_READ_CONNECTIONS', 'SMALL_WINDOW', 'MIN_AGE_S'),
    'rule_thresholds': ('C2_MIN_HISTORY', 'C2_MIN_IAT_MEAN_S', 'C2_MAX_IAT_CV', 'RECON_MIN_FANOUT',
                        'RECON_ALERT_FLOOR', 'EXFIL_BYTES_60S', 'SLOW_C2_MIN_EVENTS', 'SLOW_C2_MIN_MEAN_S',
                        'SLOW_C2_MAX_MEAN_S', 'SLOW_C2_MAX_CV'),
}
ALLOWED = {f'{module}.{name}' for module, names in TUNABLE.items() for name in names}


class SweepError(ValueError):
    """The grid or the inputs cannot be used for a sound sweep."""


def parse_grid(path):
    try:
        grid = json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SweepError(f'{path}: unreadable grid ({exc})') from exc
    if not isinstance(grid, dict) or not grid:
        raise SweepError(f'{path}: grid must be a nonempty object of parameter -> list of values')
    for key, values in grid.items():
        if key not in ALLOWED:
            raise SweepError(f'{key}: not tunable; choose from {sorted(ALLOWED)}')
        if (not isinstance(values, list) or not values
                or any(isinstance(v, bool) or not isinstance(v, (int, float)) for v in values)):
            raise SweepError(f'{key}: values must be a nonempty list of numbers')
    combinations = 1
    for values in grid.values():
        combinations *= len(values)
    if combinations > MAX_COMBINATIONS:
        raise SweepError(f'grid has {combinations} combinations; the limit is {MAX_COMBINATIONS}')
    return grid


@contextmanager
def overrides(settings):
    """Apply threshold overrides for one run and always restore the originals."""
    saved = {}
    try:
        for key, value in settings.items():
            module, name = key.split('.')
            saved[key] = getattr(MODULES[module], name)
            setattr(MODULES[module], name, value)
        yield
    finally:
        for key, value in saved.items():
            module, name = key.split('.')
            setattr(MODULES[module], name, value)


def objective(summary):
    """(mean episode recall over classes with episodes, benign false alerts per 1,000, mean precision)."""
    rows = [row for row in summary['threats'].values() if row['episodes']]
    recall = sum(row['episode_recall'] or 0 for row in rows) / len(rows) if rows else 0.0
    precisions = [row['alert_precision'] for row in rows if row['alert_precision'] is not None]
    benign = summary['benign']['false_alerts_per_1000_events'] or 0.0
    return recall, benign, sum(precisions) / len(precisions) if precisions else 0.0


def sweep(grid, label_paths, max_false_alerts):
    for path in label_paths:
        if load(path).split == 'test':
            raise SweepError(f'{path}: split "test" is scored once at the end and is never swept; '
                             'use train or validation captures')
    keys = sorted(grid)
    results = []
    for values in itertools.product(*(grid[key] for key in keys)):
        settings = dict(zip(keys, values))
        with overrides(settings):
            summary = evaluate_lab.evaluate(label_paths)['summary']['all']
        recall, false_alerts, precision = objective(summary)
        results.append(dict(settings=settings, mean_episode_recall=round(recall, 4),
                            false_alerts_per_1000_benign_events=false_alerts,
                            mean_alert_precision=round(precision, 4),
                            within_false_alert_cap=false_alerts <= max_false_alerts,
                            per_threat={name: dict(recall=row['episode_recall'], precision=row['alert_precision'])
                                        for name, row in summary['threats'].items() if row['episodes'] or row['alerts']}))
    ranked = sorted(results, key=lambda r: (not r['within_false_alert_cap'], -r['mean_episode_recall'],
                                            r['false_alerts_per_1000_benign_events'], -r['mean_alert_precision']))
    best = ranked[0] if ranked and ranked[0]['within_false_alert_cap'] else None
    return dict(format='ps26145-lab-sweep/1', max_false_alerts_per_1000=max_false_alerts,
                splits=sorted({load(p).split for p in label_paths}), combinations=len(results),
                best=best, ranked=ranked,
                note=('No setting met the false-alert cap; relax it or collect more benign look-alike runs.'
                      if best is None else 'Apply the best settings deliberately, then confirm on the held-out '
                      'validation split before the single test-split run.'))


def main(argv=None):
    parser = argparse.ArgumentParser(description='Sweep thresholds on labelled lab captures (read-only).')
    parser.add_argument('grid', type=Path)
    parser.add_argument('labels', nargs='+', type=Path)
    parser.add_argument('--max-false-alerts', type=float, default=1.0,
                        help='cap on benign false alerts per 1,000 benign events (default 1.0)')
    parser.add_argument('--out', type=Path)
    args = parser.parse_args(argv)
    try:
        report = sweep(parse_grid(args.grid), args.labels, args.max_false_alerts)
    except (SweepError, LabelError, ValueError, OSError) as exc:
        parser.exit(2, f'error: {exc}\n')
    if args.out:
        inputs = {path.resolve() for path in (args.grid, *args.labels)}
        if args.out.resolve() in inputs:
            parser.exit(2, 'error: --out would overwrite an input\n')
        args.out.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(f'{report["combinations"]} combination(s) over splits {report["splits"]}')
    for row in report['ranked'][:10]:
        mark = '*' if row['within_false_alert_cap'] else ' '
        print(f'{mark} recall {row["mean_episode_recall"]:.3f}  FA/1000 {row["false_alerts_per_1000_benign_events"]:.2f}  '
              f'precision {row["mean_alert_precision"]:.3f}  {row["settings"]}')
    print(report['note'])
    return 0


if __name__ == '__main__':
    sys.exit(main())
