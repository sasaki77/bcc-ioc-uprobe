import random

from opentelemetry.sdk.trace.id_generator import IdGenerator


class CustomIdGen(IdGenerator):

    def __init__(self):
        super().__init__()
        self._tid = None
        self._sid = None

    def set_generate_span_id_arguments(self, tid, sid):
        self._tid = tid
        self._sid = sid

    def generate_span_id(self) -> int:
        return random.getrandbits(64) if self._sid is None else self._sid

    def generate_trace_id(self) -> int:
        return random.getrandbits(128) if self._tid is None else self._tid
