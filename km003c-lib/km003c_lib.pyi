"""Type stubs for km003c_lib (KM003C Protocol Parser)

Python bindings for the KM003C USB-C power analyzer protocol library.
"""

from typing import Optional, List

# USB Device Constants
VID: int  # 0x5FC9 - ChargerLAB Vendor ID
PID: int  # 0x0063 - KM003C Product ID


class AdcData:
    """ADC measurement data from single sample."""
    
    vbus_v: float  # VBUS voltage in volts
    ibus_a: float  # IBUS current in amperes (signed)
    power_w: float  # Calculated power in watts
    vbus_avg_v: float  # VBUS averaged
    ibus_avg_a: float  # IBUS averaged
    temp_c: float  # Internal temperature in Celsius
    vdp_v: float  # USB D+ line voltage
    vdm_v: float  # USB D- line voltage
    vdp_avg_v: float  # D+ averaged
    vdm_avg_v: float  # D- averaged
    cc1_v: float  # USB-C CC1 line voltage
    cc2_v: float  # USB-C CC2 line voltage
    
    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...


class AdcQueueSample:
    """Single buffered sample from AdcQueue."""
    
    sequence: int  # Sample sequence number
    vbus_v: float  # VBUS voltage in volts
    ibus_a: float  # IBUS current in amperes (signed)
    power_w: float  # Calculated power in watts
    cc1_v: float  # USB-C CC1 line voltage
    cc2_v: float  # USB-C CC2 line voltage
    vdp_v: float  # USB D+ line voltage
    vdm_v: float  # USB D- line voltage
    
    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...


class AdcQueueData:
    """Multi-sample buffered data (5-50 samples per request)."""
    
    samples: List[AdcQueueSample]
    
    def has_dropped_samples(self) -> bool:
        """Check for gaps in sequence numbers indicating dropped samples."""
        ...
    
    def sequence_range(self) -> Optional[tuple[int, int]]:
        """Get (first_seq, last_seq) tuple, or None if no samples."""
        ...
    
    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...


class PdStatus:
    """PD status measurement snapshot (12 bytes, appears with ADC+PD)."""
    
    type_id: int
    timestamp: int  # 24-bit timestamp, ~40ms per tick
    vbus_v: float
    ibus_a: float
    cc1_v: float
    cc2_v: float
    
    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...


class PdPreamble:
    """PD event stream preamble (12 bytes at start of PD-only packets)."""
    
    timestamp: int  # Millisecond timestamp
    vbus_v: float
    ibus_a: float
    cc1_v: float
    cc2_v: float
    
    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...


class PdEvent:
    """Single PD event (connect/disconnect/message)."""
    
    timestamp: int
    event_type: str  # "connect", "disconnect", or "pd_message"
    sop: Optional[int]  # SOP type for PD messages
    wire_data: Optional[List[int]]  # Raw PD wire bytes for messages
    
    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...


class PdEventStream:
    """Complete PD event stream with preamble and events."""
    
    preamble: PdPreamble
    events: List[PdEvent]
    
    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...


class Packet:
    """High-level semantic packet after protocol interpretation.
    
    Packet types:
    - "DataResponse": Device response with payload data
    - "GetData": Request for data with attribute mask
    - "Connect": Connection command
    - "Disconnect": Disconnection command
    - "StartGraph": Start AdcQueue streaming
    - "StopGraph": Stop AdcQueue streaming
    - "Accept": Command acknowledgment
    - "Generic": Unrecognized packet types
    """
    
    packet_type: str
    
    # Payload data (chained logical packets - multiple can be present)
    adc_data: Optional[AdcData]  # Single ADC sample
    adcqueue_data: Optional[AdcQueueData]  # Multi-sample buffered data
    pd_status: Optional[PdStatus]  # PD status snapshot
    pd_events: Optional[PdEventStream]  # PD event stream
    raw_payload: Optional[bytes]  # Unknown/Generic payloads
    
    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...


class RawPacket:

    # Data variant shape for PutData responses (Python dict variant)
    # {
    #   "Data": {
    #       "header": {"packet_type": int, "reserved_flag": bool, "id": int, "obj_count_words": int},
    #       "logical_packets": List[Dict[str, Any]]  # [{"attribute": int, "next": bool, "chunk": int, "size": int, "payload": bytes}]
    #   }
    # }

    """Low-level packet structure showing raw protocol details."""
    
    packet_type: str
    packet_type_id: int
    id: int  # Transaction ID (0-255)
    has_extended_header: bool
    reserved_flag: bool
    
    # Extended header fields (only for PutData packets)
    ext_attribute_id: Optional[int]
    ext_next: Optional[bool]
    ext_chunk: Optional[int]
    ext_size: Optional[int]
    
    # Attribute info
    attribute: Optional[str]
    attribute_id: Optional[int]
    
    payload: bytes
    raw_bytes: bytes
    
    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...


class SampleRate:
    """Device sample rate information."""
    
    hz: int  # Sample rate in Hz
    name: str  # Human-readable name
    
    def __repr__(self) -> str: ...
    def __str__(self) -> str: ...


# Protocol Constants

# Command types (PacketType enum)
CMD_SYNC: int
CMD_CONNECT: int
CMD_DISCONNECT: int
CMD_ACCEPT: int
CMD_REJECT: int
CMD_GET_DATA: int
CMD_START_GRAPH: int
CMD_STOP_GRAPH: int

# Attributes (Attribute enum)
ATT_ADC: int
ATT_ADC_QUEUE: int
ATT_ADC_QUEUE_10K: int
ATT_SETTINGS: int
ATT_PD_PACKET: int
ATT_PD_STATUS: int
ATT_QC_PACKET: int

# Sample rates (GraphSampleRate enum)
RATE_1_SPS: int
RATE_10_SPS: int
RATE_50_SPS: int
RATE_1000_SPS: int


# Parsing Functions

def parse_packet(data: bytes) -> Packet:
    """Parse packet bytes into high-level semantic representation.
    
    Args:
        data: Complete packet bytes including headers
        
    Returns:
        Packet with semantic meaning and parsed payloads
        
    Raises:
        ValueError: If packet bytes are malformed
    """
    ...


def parse_raw_packet(data: bytes) -> RawPacket:
    """Parse packet bytes into low-level protocol structure.
    
    Args:
        data: Complete packet bytes including headers
        
    Returns:
        RawPacket with protocol details and bitfield values
        
    Raises:
        ValueError: If packet bytes are malformed
    """
    ...


def parse_raw_adc_data(data: bytes) -> AdcData:
    """Parse raw ADC data bytes directly (44 bytes).
    
    Args:
        data: Raw ADC payload bytes (must be exactly 44 bytes)
        
    Returns:
        AdcData with processed measurements
        
    Raises:
        ValueError: If data is not correct size
    """
    ...


def get_sample_rates() -> List[SampleRate]:
    """Get list of all supported device sample rates.
    
    Returns:
        List of SampleRate objects (1, 10, 50, 1000, 10000 SPS)
    """
    ...


# Packet Creation

def create_packet(packet_type: int, transaction_id: int, data: int) -> bytes:
    """Create a protocol packet as bytes ready to send over USB.
    
    Universal packet creation function - use with CMD_* and ATT_* constants.
    
    Args:
        packet_type: Command type (use CMD_* constants)
        transaction_id: Transaction ID (0-255)
        data: Data word - meaning depends on packet_type:
              - For GetData: attribute mask (ATT_ADC, ATT_ADC_QUEUE, etc.)
              - For StartGraph: rate index (RATE_1_SPS, RATE_50_SPS, etc.)
              - For Connect/StopGraph: 0
    
    Returns:
        4-byte packet ready to send over USB
        
    Examples:
        >>> create_packet(CMD_CONNECT, 1, 0)
        b'\\x02\\x01\\x00\\x00'
        
        >>> create_packet(CMD_GET_DATA, 2, ATT_ADC)
        b'\\x0c\\x02\\x02\\x00'
        
        >>> create_packet(CMD_START_GRAPH, 3, RATE_50_SPS)
        b'\\x0e\\x03\\x04\\x00'
    """
    ...