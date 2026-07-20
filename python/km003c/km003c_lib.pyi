"""Types for the native KM003C protocol parser extension."""

from typing import Any, Dict, List, Optional, Tuple

VID: int
PID: int

CMD_SYNC: int
CMD_CONNECT: int
CMD_DISCONNECT: int
CMD_ACCEPT: int
CMD_REJECT: int
CMD_GET_DATA: int
CMD_START_GRAPH: int
CMD_STOP_GRAPH: int

ATT_ADC: int
ATT_ADC_QUEUE: int
ATT_ADC_QUEUE_10K: int
ATT_SETTINGS: int
ATT_PD_PACKET: int

RATE_2_SPS: int
RATE_10_SPS: int
RATE_50_SPS: int
RATE_1000_SPS: int

class SampleRate:
    @property
    def hz(self) -> int: ...
    @property
    def name(self) -> str: ...
    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...

class AdcData:
    vbus_v: float
    ibus_a: float
    power_w: float
    vbus_avg_v: float
    ibus_avg_a: float
    temp_c: float
    vdp_v: float
    vdm_v: float
    vdp_avg_v: float
    vdm_avg_v: float
    cc1_v: float
    cc2_v: float
    cc2_avg_v: float
    internal_vdd_v: float
    sample_rate: SampleRate
    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...

class AdcQueueSample:
    sequence: int
    vbus_v: float
    ibus_a: float
    power_w: float
    cc1_v: float
    cc2_v: float
    vdp_v: float
    vdm_v: float
    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...

class AdcQueueData:
    samples: List[AdcQueueSample]
    def sequence_range(self) -> Optional[Tuple[int, int]]: ...
    def has_dropped_samples(self, rate_index: int) -> bool: ...
    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...

class PdStatus:
    timestamp: float
    vbus_v: float
    ibus_a: float
    cc1_v: float
    cc2_v: float
    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...

class PdPreamble:
    timestamp: float
    vbus_v: float
    ibus_a: float
    cc1_v: float
    cc2_v: float
    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...

PdEventData = Dict[str, Any]

class PdEvent:
    timestamp: float
    data: PdEventData
    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...

class PdEventStream:
    @property
    def preamble(self) -> PdPreamble: ...
    @property
    def events(self) -> List[PdEvent]: ...
    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...

class LogicalPacket:
    attribute: int
    next: bool
    chunk: int
    size: int
    payload: List[int]

# PyO3 converts the Rust enums to one-key dictionaries whose key is the
# active variant, for example {"Accept": {"id": 3}}.
Packet = Dict[str, Any]
RawPacket = Dict[str, Any]

def parse_packet(data: bytes) -> Packet: ...
def parse_raw_packet(data: bytes) -> RawPacket: ...
def parse_raw_adc_data(data: bytes) -> AdcData: ...
def get_sample_rates() -> List[SampleRate]: ...
def create_packet(packet_type: int, transaction_id: int, data: int) -> bytes: ...
