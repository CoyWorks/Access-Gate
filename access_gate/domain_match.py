"""Shared exact/suffix matching for already-normalized runtime hostnames."""
def match_rule(name,exact,suffix):
    if name in exact:return name,False
    parts=name.split('.')
    for index in range(len(parts)-1):
        candidate='.'.join(parts[index:])
        if candidate in suffix:return candidate,True
    return None
