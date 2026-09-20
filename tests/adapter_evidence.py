"""Independently bind actual-device evidence to this boot's pinned probe inventory."""
import hashlib
import json
import re


def verify_selection(record, files, baseline, policy):
    env = record['fixture']['environment']
    selection = env['adapterSelection']
    if baseline['schema'] != 'd3d11-native-environment-baseline/v4' or baseline['adapterSelection'] != 'unique-current-inventory':
        raise ValueError('Unapproved adapter selection policy')
    data = files['selection-adapters.json']
    inventory = json.loads(data)
    if inventory['schema'] != 'd3d11-adapter-inventory/v2' or inventory['qualified'] is not False:
        raise ValueError('Unqualified inventory contract')
    if (selection['mode'] != 'unique-current-inventory' or
            selection['inventorySha256'] != hashlib.sha256(data).hexdigest() or
            selection['probeSha256'] != policy['files']['device-probe.exe']):
        raise ValueError('Unbound inventory')
    boot = env['bootUtc']
    if (not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{7}Z', boot) or
            boot != selection['bootUtc'] or boot != record['session']['bootUtc']):
        raise ValueError('Boot identity drift')
    entries = inventory['adapters']
    required = {'ordinal', 'name', 'vendorId', 'deviceId', 'subsystemId', 'revision', 'flags',
                'dedicatedVideoMemory', 'luidLow', 'luidHigh'}
    if not 1 <= len(entries) <= 64:
        raise ValueError('Invalid inventory count')
    seen = set()
    matches = []
    pin = baseline['adapter']
    if set(pin) != {'name', 'vendorId', 'deviceId', 'subsystemId', 'revision', 'software'} or pin['software'] is not False:
        raise ValueError('Invalid hardware pin')
    for ordinal, entry in enumerate(entries):
        if set(entry) != required or entry['ordinal'] != ordinal or not isinstance(entry['name'], str):
            raise ValueError('Invalid inventory shape')
        for field in required - {'name'}:
            maximum = 2**50 if field == 'dedicatedVideoMemory' else 2**32-1
            if type(entry[field]) is not int or not 0 <= entry[field] <= maximum:
                raise ValueError('Invalid inventory integer')
        if entry['flags'] & ~3:
            raise ValueError('Unknown adapter flags')
        luid = (entry['luidLow'], entry['luidHigh'])
        if luid in seen:
            raise ValueError('Duplicate LUID')
        seen.add(luid)
        if entry['flags'] == 0 and all(entry[k] == v for k, v in pin.items() if k != 'software'):
            matches.append(entry)
    if len(matches) != 1 or selection['adapter'] != matches[0]:
        raise ValueError('Ambiguous or mismatched adapter selection')
    selected = matches[0]
    actual = env['adapter']
    expected = {k: selected[k] for k in ('name', 'vendorId', 'deviceId', 'subsystemId', 'revision', 'luidLow', 'luidHigh')}
    expected['software'] = False
    if 'ordinal' in actual:
        expected['ordinal'] = selected['ordinal']
    if (actual != expected or actual.get('software') is not False or
            any(type(actual[k]) is not int for k in expected if k not in ('name', 'software'))):
        raise ValueError('Actual device differs from selection')
