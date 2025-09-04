"""
KM003C Python bindings

This package provides Python bindings for parsing KM003C USB power meter data.
"""

from .km003c_lib import (
    AdcData,
    SampleRate,
    parse_raw_adc_data,
    parse_packet,
    get_sample_rates,
    VID,
    PID,
)

__all__ = [
    "AdcData",
    "SampleRate", 
    "parse_raw_adc_data",
    "parse_packet",
    "get_sample_rates",
    "VID",
    "PID",
]

__version__ = "0.1.0"