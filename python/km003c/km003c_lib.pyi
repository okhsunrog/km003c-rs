"""Types for the native KM003C protocol parser extension."""

from typing import Any

VID: int
PID: int
__version__: str

CMD_SYNC: int
CMD_CONNECT: int
CMD_DISCONNECT: int
CMD_ACCEPT: int
CMD_REJECT: int
CMD_GET_DATA: int
CMD_START_GRAPH: int
CMD_STOP_GRAPH: int
CMD_ENABLE_PD_MONITOR: int
CMD_DISABLE_PD_MONITOR: int
CMD_MEMORY_READ: int
CMD_STREAMING_AUTH: int

ATT_ADC: int
ATT_ADC_QUEUE: int
ATT_ADC_QUEUE_10K: int
ATT_SETTINGS: int
ATT_PD_PACKET: int
ATT_PD_TRACE: int
ATT_LOG_METADATA: int

RATE_2_SPS: int
RATE_10_SPS: int
RATE_50_SPS: int
RATE_1000_SPS: int

INTERFACE_VENDOR: int
ENDPOINT_OUT_VENDOR: int
ENDPOINT_IN_VENDOR: int
INTERFACE_HID: int
ENDPOINT_OUT_HID: int
ENDPOINT_IN_HID: int

ADDR_DEVICE_INFO: int
ADDR_FIRMWARE_INFO: int
ADDR_CALIBRATION: int
ADDR_PREFERRED_CALIBRATION: int
ADDR_HARDWARE_ID: int
ADDR_OFFLINE_LOG: int
INFO_BLOCK_SIZE: int
HARDWARE_ID_SIZE: int
LOG_METADATA_SIZE: int
OFFLINE_LOG_SAMPLE_SIZE: int

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
    sample_rate: SampleRate | None
    sample_rate_raw: int
    vendor_flags: int
    vbus_uncalibrated_average_raw: int
    ibus_uncalibrated_average_raw: int
    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...

class AdcQueueSample:
    sequence: int
    marker: int
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
    rate_index: int
    samples: list[AdcQueueSample]
    def sequence_range(self) -> tuple[int, int] | None: ...
    def has_dropped_samples(self) -> bool: ...
    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...

class AdcQueueSampleRaw:
    sequence: int
    marker: int
    vbus_uv: int
    ibus_ua: int
    cc1_raw: int
    cc2_raw: int
    vdp_raw: int
    vdm_raw: int

class AdcQueueRawData:
    samples: list[AdcQueueSampleRaw]
    def decode(self, rate_index: int) -> AdcQueueData: ...
    def sequence_range(self) -> tuple[int, int] | None: ...
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

# One-key dictionary naming the active variant: {"Connect": None},
# {"Disconnect": None} or {"PdMessage": {"sop": int, "wire_data": list[int]}}.
PdEventData = dict[str, Any]

class PdEvent:
    timestamp: float
    data: PdEventData
    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...

class PdEventStream:
    @property
    def preamble(self) -> PdStatus: ...
    @property
    def events(self) -> list[PdEvent]: ...
    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...

class PdTraceStateEvent:
    @property
    def state_code(self) -> int: ...
    @property
    def state_name(self) -> str: ...
    @property
    def timestamp_seconds(self) -> float: ...

class PdTraceProtocolEvent:
    @property
    def code(self) -> int: ...
    @property
    def event_name(self) -> str: ...
    @property
    def timestamp_seconds(self) -> float: ...

class PdTrace:
    @property
    def state_events(self) -> list[PdTraceStateEvent]: ...
    @property
    def protocol_events(self) -> list[PdTraceProtocolEvent]: ...

class LogMetadata:
    @property
    def filename(self) -> str: ...
    @property
    def filename_raw(self) -> list[int]: ...
    @property
    def unknown_0x10(self) -> int: ...
    @property
    def sample_count(self) -> int: ...
    @property
    def interval_ms(self) -> float: ...
    @property
    def flags(self) -> int: ...
    @property
    def recorded_duration_s(self) -> float: ...
    @property
    def calculated_duration_s(self) -> float: ...
    @property
    def final_charge_uah(self) -> int: ...
    @property
    def final_energy_uwh(self) -> int: ...
    @property
    def data_offset(self) -> int: ...
    @property
    def data_size(self) -> int: ...
    @property
    def data_address(self) -> int: ...
    @property
    def reserved_tail(self) -> list[int]: ...
    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...

class LogicalPacket:
    attribute: int
    next: bool
    chunk: int
    size: int
    payload: list[int]

# PyO3 converts the Rust enums to one-key dictionaries whose key is the
# active variant, for example {"Accept": {"id": 3}}.
Packet = dict[str, Any]
RawPacket = dict[str, Any]

def parse_packet(data: bytes) -> Packet: ...
def parse_packet_with_graph_rate(data: bytes, rate_index: int) -> Packet: ...
def parse_raw_packet(data: bytes) -> RawPacket: ...
def parse_raw_adc_data(data: bytes) -> AdcData: ...
def get_sample_rates() -> list[SampleRate]: ...
def create_packet(packet_type: int, transaction_id: int, data: int) -> bytes: ...

# Authenticated commands. Use these instead of re-implementing the AES keys,
# CRC layout and header framing in Python.
def build_memory_read_packet(address: int, size: int, transaction_id: int) -> bytes: ...
def decrypt_memory_payload(ciphertext: bytes) -> bytes: ...
def parse_memory_read_confirmation(packet: bytes) -> tuple[int, int] | None: ...
def build_streaming_auth_packet(credential: bytes, transaction_id: int) -> bytes: ...
def parse_streaming_auth_response(response: bytes) -> dict[str, Any] | None: ...
def parse_log_metadata(data: bytes) -> LogMetadata: ...
def parse_offline_log_samples(data: bytes) -> list[dict[str, int]]: ...
