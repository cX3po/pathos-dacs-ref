#!/usr/bin/env python3
"""Offline inventory/citation checks, never a proof of semantic equivalence."""
import argparse
import ast
from collections import deque
from dataclasses import fields
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import subprocess

ROOT = Path(__file__).resolve().parent
PIN = '4bb9e48a1095ab32c06c25b7c0b52018d3ce4091'
URL = f'https://github.com/DACS-Agent-commerce/DACS-Standard/blob/{PIN}/spec/DACS-4-SETTLE.md'


def checkout_revision(root):
    """Return the checkout root and HEAD using the real Git reader."""
    def git(*args):
        return subprocess.run(['git', '-C', str(root), *args], check=True,
                              capture_output=True, text=True, timeout=30).stdout.strip()
    return Path(git('rev-parse', '--show-toplevel')).resolve(), git('rev-parse', 'HEAD')


def load_spec(spec_dir, mapping, *, revision_reader=checkout_revision):
    """Read only mapped chapter bytes from an exact local Git checkout."""
    root = Path(spec_dir).resolve(strict=True)
    checkout_root, revision = revision_reader(root)
    if checkout_root != root:
        raise ValueError('--spec-dir must be the checkout root')
    if revision != PIN or mapping['spec_commit'] != PIN:
        raise ValueError('specification commit differs from the required pin')
    chapter = root / 'spec/DACS-4-SETTLE.md'
    if chapter.is_symlink() or chapter.resolve() != root / 'spec/DACS-4-SETTLE.md':
        raise ValueError('specification chapter must be a regular local file')
    source = chapter.read_bytes()
    if hashlib.sha256(source).hexdigest() != mapping['spec_sha256']:
        raise ValueError('pinned specification bytes changed')
    return source


def synthetic_fixture(mapping):
    """Minimal artificial citation text; no upstream specification is embedded."""
    from copy import deepcopy
    fixture = deepcopy(mapping)
    sections = sorted({r['section'] for row in mapping['elements'].values() for r in row['refs']})
    lines = []
    refs = {}
    for index, section in enumerate(sections):
        heading = '# Synthetic clause ' + str(index + 1)
        lines += [heading, 'Synthetic MUST placeholder ' + str(index + 1)]
        refs[section] = dict(section=heading, clause_id='Synthetic', lines=[len(lines), len(lines)],
                             sha256=hashlib.sha256(lines[-1].encode()).hexdigest())
    source = ('\n'.join(lines) + '\n').encode()
    fixture['spec_sha256'] = hashlib.sha256(source).hexdigest()
    for row in fixture['elements'].values():
        row['refs'] = [deepcopy(refs[r['section']]) for r in row['refs']]
    return fixture, source


def model():
    mapping = json.loads((ROOT/'mapping.json').read_text(encoding='utf-8'))
    if hashlib.sha256((ROOT/'model/explore.py').read_bytes()).hexdigest() != mapping['model_sha256']:
        raise ValueError('model bytes changed; re-review inventory and interpretations')
    spec = importlib.util.spec_from_file_location('payment_model', ROOT/'model/explore.py')
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def inventory(m):
    """Full reachable reference closure; static invariant names include untriggered checks."""
    queue = deque([m.State()])
    seen = {m.State()}
    elements = {'field:'+f.name for f in fields(m.State)}
    while queue:
        s = queue.popleft()
        for label, value in [('journal', s.journal), ('truth', s.truth), ('read', s.read)]:
            elements.add(f'state:{label}:{value}')
        elements.update('state:worker:'+v for v in s.workers)
        for event, t in m.successors(s, 'reference'):
            elements.add('transition:'+re.sub(r'^w[01]\.', '', event))
            if m.violation(s, event, t):
                raise ValueError('reference invariant failed')
            if t not in seen:
                seen.add(t)
                queue.append(t)
    tree = ast.parse((ROOT/'model/explore.py').read_text())
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'violation')
    elements.update('invariant:'+n.value.value for n in ast.walk(fn)
                    if isinstance(n, ast.Return) and isinstance(n.value, ast.Constant)
                    and isinstance(n.value.value, str))
    return elements, len(seen)


def validate(mapping, elements, source):
    errors = []
    if hashlib.sha256(source).hexdigest() != mapping['spec_sha256']:
        errors.append('pinned specification bytes changed')
    if hashlib.sha256((ROOT/'model/explore.py').read_bytes()).hexdigest() != mapping['model_sha256']:
        errors.append('model bytes changed; re-review inventory and interpretations')
    if set(mapping['elements']) != elements:
        errors.append('model inventory differs: '+str(sorted(elements ^ set(mapping['elements']))))
    lines = source.decode().splitlines()
    for key, row in mapping['elements'].items():
        if row['kind'] not in ('partial', 'assumption') or not row['rationale']:
            errors.append(key+': missing explicit scope')
        for ref in row['refs']:
            a,b = ref['lines']
            text = '\n'.join(lines[a-1:b])
            if not 1 <= a <= b <= len(lines) or hashlib.sha256(text.encode()).hexdigest() != ref['sha256']:
                errors.append(key+': invalid clause span')
            heading = ''
            for line in lines[:a]:
                if line.startswith('#'):
                    heading = line
            if heading != ref['section'] or heading.lstrip('# ').split(' ', 1)[0] != ref['clause_id']:
                errors.append(key+': section mismatch')
        if not row['refs']:
            errors.append(key+': missing context citation')
    return errors


def probes(m, mapping, elements):
    """Negative controls: citation corruption, missing mapping, and behavioral misreadings."""
    from copy import deepcopy
    mapping, source = synthetic_fixture(mapping)
    if validate(mapping, elements, source):
        raise ValueError("synthetic fixture must validate before mutation")
    results = []
    bad = deepcopy(mapping)
    del bad['elements'][sorted(elements)[0]]
    results.append(('unmapped_model_element', bool(validate(bad,elements,source))))
    bad = deepcopy(mapping)
    bad['elements'][sorted(elements)[0]]['refs'][0]['lines'] = [1,1]
    results.append(('wrong_clause_span', bool(validate(bad,elements,source))))
    results.append(('changed_spec', bool(validate(mapping,elements,source+b'\n'))))
    # Independent clause-derived expectations, evaluated against successor behavior,
    # rather than merely trusting the mutant's own invariant oracle.
    s = m.State(journal='intent', workers=('intent','idle'), intent=True,
                calls=1, effects=1, truth='included', read='STALE', reset=True)
    def can_deliver(variant):
        return any(e.endswith('deliver.effect') for e,_ in m.successors(s,variant))
    results.append(('PIPE-3_native_STALE_is_not_included',
                    not can_deliver('reference') and can_deliver('deliver_on_stale')))
    s = m.State(journal='intent',workers=('intent','idle'),intent=True,
                calls=1,truth='unresolved',read='MISSING',reserved=True)
    def can_release(variant):
        return any(e.endswith('release.intent') for e,_ in m.successors(s,variant))
    results.append(('assumption_MISSING_is_not_failed_proven',
                    not can_release('reference') and can_release('release_on_missing')))
    # The second is a local stronger-safety assumption, not a native DACS MUST.
    return results


def report(mapping, elements, count, source, results):
    lines = source.decode().splitlines()
    out = ['# Payment model traceability (non-normative)', '',
           f'Specification pin: `{PIN}`; model reference closure: {count} states.', '',
           'Inventory/citation integrity PASS does not establish that the model interprets the Standard correctly.',
           'All normative connections below are partial abstractions. Assumptions have no exact normative counterpart;',
           'their citations provide context only. No normative MUST is claimed fully modelled.',
           'Scope: the complete DACS-4-SETTLE.md file only; other chapters and SDK behavior are not checked.', '',
           '## Model → specification', '', '| Element | Classification | Section and pinned lines | Rationale |',
           '|---|---|---|---|']
    for key in sorted(elements):
        row = mapping['elements'][key]
        refs = ', '.join(f"[{r['section']}]({URL}#L{r['lines'][0]}-L{r['lines'][1]})" for r in row['refs'])
        out.append(f"| `{key}` | {row['kind']} | {refs} | {row['rationale']} |")
    out += ['', '## Unmapped model elements (assumptions; context is not normative authority)', '']
    out += ['- `'+k+'`: '+v['rationale'] for k,v in sorted(mapping['elements'].items()) if v['kind']=='assumption']
    out += ['', '## Specification → model: unmodelled or only partially modelled MUST/SHALL lines', '',
            'Lexical uppercase MUST/SHALL inventory includes comments/examples and does not parse legal applicability.',
            'A line may contain multiple obligations; all are retained as gaps. No complete-conformance claim.', '']
    section = ''
    for n,line in enumerate(lines,1):
        if line.startswith('#'): section = line
        if re.search(r'\b(?:MUST|SHALL)\b',line):
            linked = [k for k,v in mapping['elements'].items() if v['kind']=='partial'
                      and any(a<=n<=b for r in v['refs'] for a,b in [r['lines']])]
            out.append(f'- [{section}, L{n}]({URL}#L{n}): '+
                       ('partial connections: '+', '.join('`'+k+'`' for k in linked) if linked else 'unmodelled'))
    out += ['', '## Mutation probes', '']
    out += [f'- {name}: {"CAUGHT" if passed else "FAILED"}' for name,passed in results]
    out += ['', 'These probes catch selected syntactic and behavioral misreadings; arbitrary wrong prose mappings can still pass.',
            'Independent clause review and a real SDK adapter remain necessary.', '']
    return '\n'.join(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--spec-dir', type=Path, required=True,
                        help='local DACS-Standard checkout root at the documented pin')
    parser.add_argument('--inventory', action='store_true')
    parser.add_argument('--require-complete', action='store_true')
    args = parser.parse_args()
    try:
        mapping = json.loads((ROOT/'mapping.json').read_text(encoding='utf-8'))
        source = load_spec(args.spec_dir, mapping)
        m = model()
        elements,count = inventory(m)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(json.dumps({'status': 'FAIL', 'error': str(exc)}))
        return 1
    if args.inventory:
        print(json.dumps(sorted(elements),indent=2))
        return 0
    errors = validate(mapping,elements,source)
    if errors:
        print(json.dumps({'status':'FAIL','errors':errors}));return 1
    results = probes(m,mapping,elements)
    if not all(p for _,p in results):
        print(json.dumps({'status':'FAIL','probes':results}));return 1
    (ROOT/'REPORT.md').write_text(report(mapping,elements,count,source,results), encoding='utf-8')
    print(json.dumps({'integrity':'PASS','interpretation':'INCOMPLETE','elements':len(elements),
                      'states':count,'assumptions':sum(v['kind']=='assumption' for v in mapping['elements'].values()),
                      'normative_lines':sum(bool(re.search(r'\b(?:MUST|SHALL)\b',l)) for l in source.decode().splitlines()),
                      'probes':results}))
    return 2 if args.require_complete else 0


if __name__ == '__main__':
    sys.exit(main())
