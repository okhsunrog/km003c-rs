"""
KM003C Python bindings

This package provides Python bindings for parsing KM003C USB power meter data.
"""

from .km003c_lib import (
    # Data classes
    AdcData,
    SampleRate,
    AdcQueueSample,
    AdcQueueData,
    PdStatus,
    PdPreamble,
    PdEvent,
    PdEventStream,
    LogicalPacket,
    # Parsing functions
    parse_raw_adc_data,
    parse_packet,
    parse_raw_packet,
    get_sample_rates,
    create_packet,
    # USB constants
    VID,
    PID,
    # Command types
    CMD_SYNC,
    CMD_CONNECT,
    CMD_DISCONNECT,
    CMD_ACCEPT,
    CMD_REJECT,
    CMD_GET_DATA,
    CMD_START_GRAPH,
    CMD_STOP_GRAPH,
    # Attribute constants
    ATT_ADC,
    ATT_ADC_QUEUE,
    ATT_ADC_QUEUE_10K,
    ATT_SETTINGS,
    ATT_PD_PACKET,
    # Sample rates
    RATE_2_SPS,
    RATE_10_SPS,
    RATE_50_SPS,
    RATE_1000_SPS,
)

__all__ = [
    # Data classes
    "AdcData",
    "SampleRate",
    "AdcQueueSample",
    "AdcQueueData",
    "PdStatus",
    "PdPreamble",
    "PdEvent",
    "PdEventStream",
    "LogicalPacket",
    # Parsing functions
    "parse_raw_adc_data",
    "parse_packet",
    "parse_raw_packet",
    "get_sample_rates",
    "create_packet",
    # USB constants
    "VID",
    "PID",
    # Command types
    "CMD_SYNC",
    "CMD_CONNECT",
    "CMD_DISCONNECT",
    "CMD_ACCEPT",
    "CMD_REJECT",
    "CMD_GET_DATA",
    "CMD_START_GRAPH",
    "CMD_STOP_GRAPH",
    # Attribute constants
    "ATT_ADC",
    "ATT_ADC_QUEUE",
    "ATT_ADC_QUEUE_10K",
    "ATT_SETTINGS",
    "ATT_PD_PACKET",
    # Sample rates
    "RATE_2_SPS",
    "RATE_10_SPS",
    "RATE_50_SPS",
    "RATE_1000_SPS",
]

__version__ = "0.1.0"
