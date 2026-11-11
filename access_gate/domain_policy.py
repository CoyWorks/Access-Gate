"""Immutable, bounded domain-policy snapshots; never an access-grant cache."""
from dataclasses import dataclass
import time
from .dns_export import hostname, MAX_DOMAINS
from .core import GateError


@dataclass(frozen=True)
class DomainPolicy:
    exact: frozenset
    suffix: frozenset
    loaded: float
    max_age: float = 10.

    @classmethod
    def parse(cls,payload,clock=time.monotonic):
        rows=payload.get('domains') if isinstance(payload,dict) else None
        if not isinstance(rows,list) or len(rows)>MAX_DOMAINS:raise ValueError('Invalid policy snapshot.')
        exact=set();suffix=set()
        for row in rows:
            if not isinstance(row,dict) or type(row.get('include_subdomains')) is not bool:raise ValueError('Invalid domain scope.')
            try:name=hostname(row.get('domain'))
            except GateError as exc:raise ValueError('Invalid policy hostname.') from exc
            (suffix if row['include_subdomains'] else exact).add(name)
        return cls(frozenset(exact),frozenset(suffix),clock())

    def fresh(self,clock=time.monotonic):return 0<=clock()-self.loaded<self.max_age

    def match(self,value,clock=time.monotonic):
        if not self.fresh(clock):return None
        # Callers normalize the hostname using the shared runtime validator.
        if value in self.exact:return (value,False)
        parts=value.split('.')
        for index in range(len(parts)-1):
            candidate='.'.join(parts[index:])
            if candidate in self.suffix:return (candidate,True)
        return None
