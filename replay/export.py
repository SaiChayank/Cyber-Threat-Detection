"""Export reproducible JSONL metadata experiments; never emit network traffic."""
import argparse
import json
from pathlib import Path
from replay.scenarios import CLASSES, scenario


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', default='data/lab')
    args = parser.parse_args()
    root = Path(args.output)
    root.mkdir(parents=True, exist_ok=True)
    for label in CLASSES:
        with (root / f'{label.lower()}.jsonl').open('w') as f:
            for event in scenario(label, seed=100):
                f.write(event.model_dump_json()+'\n')
    (root / 'manifest.json').write_text(json.dumps(dict(seed=100, classes=CLASSES,
        format='metadata JSONL', provenance='synthetic offline experiments', events_per_class=32), indent=2))
    print(root.resolve())


if __name__ == '__main__':
    main()
