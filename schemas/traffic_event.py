"""Validated metadata-only event contract. Times are UTC epoch milliseconds."""
from typing import Literal
from pydantic import BaseModel, Field, IPvAnyAddress, model_serializer, model_validator

OPTIONAL_OBSERVED_FIELDS = ('tls_server_fingerprint', 'tls_ja4', 'tcp_fin_rst', 'tcp_window')


class TrafficEvent(BaseModel):
    timestamp: float = Field(ge=0, le=253402300799999, allow_inf_nan=False)
    src_ip: IPvAnyAddress
    dst_ip: IPvAnyAddress
    src_port: int = Field(default=0, ge=0, le=65535)
    dst_port: int = Field(default=0, ge=0, le=65535)
    protocol: int = Field(default=6, ge=0, le=255)
    packets: int = Field(default=1, ge=1, le=1000000)
    bytes: int = Field(default=100, ge=0, le=1000000000)
    syn: bool = False
    # Exact initial-SYN packet count; absent when an aggregate has only flags.
    syn_packets: int | None = Field(default=None, ge=0, le=1000000)
    dns_name: str | None = Field(default=None, max_length=253)
    dns_type: int = Field(default=1, ge=0, le=65535)
    tls_fingerprint: str | None = Field(default=None, max_length=256)  # Client JA3 hash
    tls_server_fingerprint: str | None = Field(default=None, max_length=256)  # Server JA3S hash
    tls_ja4: str | None = Field(default=None, max_length=64)  # Client JA4
    encrypted: bool = False
    transport: Literal['IP', 'TLS', 'QUIC'] = 'IP'
    reverse_bytes: int | None = Field(default=None, ge=0, le=1000000000)
    reverse_observed: bool = False
    flow_id: str | None = Field(default=None, max_length=128)
    tcp_fin_rst: bool | None = None  # True when an observed TCP FIN or RST closes the connection
    tcp_window: int | None = Field(default=None, ge=0, le=65535)  # Advertised (unscaled) TCP window

    @model_validator(mode='after')
    def check_reverse(self):
        if self.syn_packets is not None and self.syn_packets > self.packets:
            raise ValueError('syn_packets cannot exceed packets')
        if self.reverse_bytes is not None and not self.reverse_observed:
            raise ValueError('reverse_bytes requires explicitly observed reverse metadata')
        if self.reverse_observed and self.reverse_bytes is None:
            raise ValueError('reverse_observed requires reverse_bytes')
        return self

    @model_serializer(mode='wrap')
    def omit_absent_observed_fields(self, handler):
        # Events without JA3S/JA4/FIN-RST serialize exactly as before these fields existed,
        # keeping exported streams and their recorded hashes byte-identical.
        data = handler(self)
        for key in OPTIONAL_OBSERVED_FIELDS:
            if data.get(key) is None:
                data.pop(key, None)
        return data
