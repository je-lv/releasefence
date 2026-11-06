"""Strict, offline JSON policy loading."""
import json
from dataclasses import dataclass, field
from pathlib import Path
from .model import Limits, RULES

@dataclass
class Policy:
    limits: Limits = field(default_factory=Limits)
    forbidden_globs: list = field(default_factory=list)
    ignore: list = field(default_factory=list)

def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result

def read_json(path):
    with open(path, encoding='utf-8') as stream:
        return json.load(stream, object_pairs_hook=strict_object,
                         parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid JSON constant')))

def load_policy(path=None):
    if path is None:
        return Policy()
    obj = read_json(path)
    allowed = {'max_file_bytes', 'max_total_bytes', 'large_file_bytes', 'forbidden_globs', 'ignore'}
    if not isinstance(obj, dict) or set(obj) - allowed:
        raise ValueError('policy must be an object with documented keys only')
    defaults = {'max_file_bytes': 10485760, 'max_total_bytes': 104857600, 'large_file_bytes': 5242880}
    for key in defaults:
        value = obj.get(key, defaults[key])
        if type(value) is not int or value <= 0:
            raise ValueError(f'policy {key} must be a positive integer')
        defaults[key] = value
    globs = obj.get('forbidden_globs', [])
    if not isinstance(globs, list) or any(not isinstance(g, str) or not g or '\\' in g for g in globs):
        raise ValueError('forbidden_globs must be nonempty forward-slash glob strings')
    ignores = obj.get('ignore', [])
    if not isinstance(ignores, list):
        raise ValueError('ignore must be an array')
    for item in ignores:
        if not isinstance(item, dict) or set(item) != {'rule_id', 'path_glob'}:
            raise ValueError('ignore entries require rule_id and path_glob only')
        if not isinstance(item['rule_id'], str) or not item['rule_id'] or not isinstance(item['path_glob'], str) or not item['path_glob'] or '\\' in item['path_glob']:
            raise ValueError('ignore entries require nonempty strings and forward-slash globs')
        if item['rule_id'] not in RULES and item['rule_id'] != 'RF400':
            raise ValueError('ignore rule_id is not a known rule')
    return Policy(Limits(**defaults), globs, ignores)
