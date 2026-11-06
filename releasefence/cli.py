"""Command line and atomic manifest operations."""
import argparse
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from . import __version__
from .core import scan
from .render import render_text, use_color
from .policy import load_policy, read_json

def encoded(obj):
    return json.dumps(obj, ensure_ascii=True, sort_keys=True, indent=2) + '\n'

def write_manifest(out, report):
    target = Path(out)
    if any(not isinstance(r['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', r['sha256']) for r in report['files']):
        raise ValueError('cannot manifest an incomplete inventory')
    payload = dict(schema_version=1, files=report['files'])
    validate_manifest(payload)
    fd, tmp = tempfile.mkstemp(prefix='.releasefence-', dir=target.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(encoded(payload))
            stream.flush()
            os.fsync(stream.fileno())
        # Atomic no-clobber publication, including races with another writer.
        os.link(tmp, target)
    finally:
        os.unlink(tmp)

def read_manifest(path):
    return validate_manifest(read_json(path))

def validate_manifest(obj):
    if not isinstance(obj, dict) or set(obj) != {'schema_version', 'files'} or type(obj['schema_version']) is not int or obj['schema_version'] != 1 or not isinstance(obj['files'], list):
        raise ValueError('invalid manifest schema')
    seen = set()
    for row in obj['files']:
        if not isinstance(row, dict) or set(row) != {'path', 'size', 'sha256'}:
            raise ValueError('invalid manifest file record')
        name = row['path']
        if not isinstance(name, str) or not name or name.startswith('/') or '\\' in name or any(p in ('', '.', '..') for p in name.split('/')) or name in seen:
            raise ValueError('invalid or duplicate manifest path')
        if type(row['size']) is not int or row['size'] < 0 or not isinstance(row['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', row['sha256']):
            raise ValueError('invalid manifest size or digest')
        seen.add(name)
    return obj

def compare(report, manifest):
    old = {r['path']: r for r in manifest['files']}
    new = {r['path']: r for r in report['files']}
    changes = []
    for path in sorted(old.keys() | new.keys()):
        kind = 'added' if path not in old else 'removed' if path not in new else 'changed' if old[path] != new[path] else None
        if kind:
            changes.append({'path': path, 'change': kind})
    report['changes'] = changes
    report['blocking'] = report['blocking'] or bool(changes)
    return report

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='releasefence',
        description='Check a source directory or ZIP before you publish it.\n'
                    'Offline; never extracts, executes or follows what it inspects.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Exit status: 0 no blocking findings, 1 blocking findings or manifest\n'
               'differences, 2 invalid input or usage.')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    commands = parser.add_subparsers(dest='command', required=True, metavar='COMMAND')
    helps = {
        'scan': 'report secrets, unsafe paths and publication mistakes',
        'manifest': 'write a JSON manifest of a clean input (never overwrites)',
        'verify': 'compare an input with a manifest: added, removed, changed',
    }
    for name in ('scan', 'manifest', 'verify'):
        cmd = commands.add_parser(name, help=helps[name], description=helps[name].capitalize() + '.')
        cmd.add_argument('path', help='directory or .zip file to inspect')
        cmd.add_argument('--policy', metavar='FILE', help='JSON policy: size limits, forbidden globs, suppressions')
        cmd.add_argument('--format', choices=('text', 'json'), default='text',
                         help='text for people (default) or stable JSON')
        cmd.add_argument('-v', '--verbose', action='store_true',
                         help='text: explain each rule, list suppressed findings and clean files')
        if name == 'manifest':
            cmd.add_argument('--out', required=True, metavar='FILE', help='manifest to create; must not exist')
        if name == 'verify':
            cmd.add_argument('--manifest', required=True, metavar='FILE', help='manifest written by releasefence manifest')
    args = parser.parse_args(argv)
    try:
        policy = load_policy(args.policy)
        if args.command == 'manifest':
            source = Path(args.path).resolve()
            output = Path(args.out).resolve()
            if output == source or source.is_dir() and output.is_relative_to(source):
                raise ValueError('manifest output must be outside the scanned input')
        report = scan(args.path, policy)
        if args.command == 'verify':
            report = compare(report, read_manifest(args.manifest))
        written = None
        if args.command == 'manifest':
            if report['blocking']:
                written = False
            else:
                write_manifest(args.out, report)
                written = args.out
        if args.format == 'json':
            print(encoded(report), end='')
        else:
            sys.stdout.write(render_text(report, args.command, args.path,
                                         color=use_color(sys.stdout), manifest_written=written,
                                         verbose=args.verbose))
        return 1 if report['blocking'] else 0
    except (OSError, ValueError, RuntimeError) as exc:
        # Do not echo filenames or malformed content from exceptions.
        message = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        print(f'releasefence: {message}', file=sys.stderr)
        return 2
