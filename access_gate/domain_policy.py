"""Immutable, bounded domain-policy snapshots; never an access-grant cache."""
from dataclasses import dataclass
import time
from .dns_export import hostname, MAX_DOMAINS
from .core import GateError
from .domain_match import match_rule


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
        return match_rule(value,self.exact,self.suffix)


    def certificate_group(self,value,suffixes):
        rule=self.match(value)
        if not rule:return None
        boundary,children=rule
        suffixes.safe_base(boundary)
        if not children or value==boundary:return boundary
        parent=value.split('.',1)[1]
        # Exactly one wildcard label; never climb above a configured boundary.
        return suffixes.safe_base(parent)
