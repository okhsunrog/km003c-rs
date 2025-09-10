use crate::adc::{AdcDataRaw, AdcDataSimple, SampleRate};
use crate::message::Packet;
use crate::packet::RawPacket;
use bytes::Bytes;
use pyo3::prelude::*;

#[pyclass(name = "AdcData")]
#[derive(Clone)]
pub struct PyAdcData {
    #[pyo3(get)]
    pub vbus_v: f64,
    #[pyo3(get)]
    pub ibus_a: f64,
    #[pyo3(get)]
    pub power_w: f64,
    #[pyo3(get)]
    pub vbus_avg_v: f64,
    #[pyo3(get)]
    pub ibus_avg_a: f64,
    #[pyo3(get)]
    pub temp_c: f64,
    #[pyo3(get)]
    pub vdp_v: f64,
    #[pyo3(get)]
    pub vdm_v: f64,
    #[pyo3(get)]
    pub vdp_avg_v: f64,
    #[pyo3(get)]
    pub vdm_avg_v: f64,
    #[pyo3(get)]
    pub cc1_v: f64,
    #[pyo3(get)]
    pub cc2_v: f64,
}

impl From<AdcDataSimple> for PyAdcData {
    fn from(data: AdcDataSimple) -> Self {
        PyAdcData {
            vbus_v: data.vbus_v,
            ibus_a: data.ibus_a,
            power_w: data.power_w,
            vbus_avg_v: data.vbus_avg_v,
            ibus_avg_a: data.ibus_avg_a,
            temp_c: data.temp_c,
            vdp_v: data.vdp_v,
            vdm_v: data.vdm_v,
            vdp_avg_v: data.vdp_avg_v,
            vdm_avg_v: data.vdm_avg_v,
            cc1_v: data.cc1_v,
            cc2_v: data.cc2_v,
        }
    }
}

#[pymethods]
impl PyAdcData {
    fn __repr__(&self) -> String {
        format!(
            "AdcData(vbus={:.3}V, ibus={:.3}A, power={:.3}W, temp={:.1}°C)",
            self.vbus_v, self.ibus_a, self.power_w, self.temp_c
        )
    }
    
    fn __str__(&self) -> String {
        self.__repr__()
    }
}

#[pyclass(name = "SampleRate")]
#[derive(Clone)]
pub struct PySampleRate {
    #[pyo3(get)]
    pub hz: u32,
    #[pyo3(get)]
    pub name: String,
}

#[pyclass(name = "Packet")]
#[derive(Clone)]
pub struct PyPacket {
    #[pyo3(get)]
    pub packet_type: String,
    #[pyo3(get)]
    pub adc_data: Option<PyAdcData>,
    #[pyo3(get)]
    pub pd_data: Option<Vec<u8>>,
    #[pyo3(get)]
    pub raw_payload: Option<Vec<u8>>,
}

impl From<Packet> for PyPacket {
    fn from(packet: Packet) -> Self {
        match packet {
            Packet::SimpleAdcData(adc_data) => PyPacket {
                packet_type: "SimpleAdcData".to_string(),
                adc_data: Some(PyAdcData::from(adc_data)),
                pd_data: None,
                raw_payload: None,
            },
            Packet::CmdGetSimpleAdcData => PyPacket {
                packet_type: "CmdGetSimpleAdcData".to_string(),
                adc_data: None,
                pd_data: None,
                raw_payload: None,
            },
            Packet::PdRawData(bytes) => PyPacket {
                packet_type: "PdRawData".to_string(),
                adc_data: None,
                pd_data: Some(bytes.to_vec()),
                raw_payload: None,
            },
            Packet::CmdGetPdData => PyPacket {
                packet_type: "CmdGetPdData".to_string(),
                adc_data: None,
                pd_data: None,
                raw_payload: None,
            },
            Packet::Generic(raw_packet) => PyPacket {
                packet_type: "Generic".to_string(),
                adc_data: None,
                pd_data: None,
                raw_payload: Some(raw_packet.payload().to_vec()),
            },
        }
    }
}

impl From<SampleRate> for PySampleRate {
    fn from(rate: SampleRate) -> Self {
        PySampleRate {
            hz: rate.as_hz(),
            name: rate.to_string(),
        }
    }
}

#[pymethods]
impl PyPacket {
    fn __repr__(&self) -> String {
        match self.packet_type.as_str() {
            "SimpleAdcData" => {
                if let Some(ref adc) = self.adc_data {
                    format!("Packet::SimpleAdcData({})", adc.__repr__())
                } else {
                    "Packet::SimpleAdcData(None)".to_string()
                }
            }
            "PdRawData" => {
                if let Some(ref data) = self.pd_data {
                    format!("Packet::PdRawData({} bytes)", data.len())
                } else {
                    "Packet::PdRawData(None)".to_string()
                }
            }
            "Generic" => {
                if let Some(ref payload) = self.raw_payload {
                    format!("Packet::Generic({} bytes payload)", payload.len())
                } else {
                    "Packet::Generic(no payload)".to_string()
                }
            }
            _ => format!("Packet::{}", self.packet_type),
        }
    }
    
    fn __str__(&self) -> String {
        self.__repr__()
    }
}

#[pymethods]
impl PySampleRate {
    fn __repr__(&self) -> String {
        format!("SampleRate({})", self.name)
    }
    
    fn __str__(&self) -> String {
        self.name.clone()
    }
}

#[pyfunction]
pub fn parse_raw_adc_data(data: &[u8]) -> PyResult<PyAdcData> {
    use zerocopy::FromBytes;
    
    let adc_raw = AdcDataRaw::ref_from_bytes(data)
        .map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>(
            format!("Invalid ADC data size: expected {}, got {}", 
                    std::mem::size_of::<AdcDataRaw>(), data.len())
        ))?;
    
    let adc_simple = AdcDataSimple::from(*adc_raw);
    Ok(PyAdcData::from(adc_simple))
}

#[pyfunction]
pub fn parse_packet(data: &[u8]) -> PyResult<PyPacket> {
    let bytes = Bytes::from(data.to_vec());
    let raw_packet = RawPacket::try_from(bytes)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{}", e)))?;
    
    let packet = Packet::try_from(raw_packet)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{}", e)))?;
    
    Ok(PyPacket::from(packet))
}

#[pyfunction]
pub fn get_sample_rates() -> Vec<PySampleRate> {
    vec![
        PySampleRate::from(SampleRate::Sps1),
        PySampleRate::from(SampleRate::Sps10),
        PySampleRate::from(SampleRate::Sps50),
        PySampleRate::from(SampleRate::Sps1000),
        PySampleRate::from(SampleRate::Sps10000),
    ]
}

#[pymodule]
fn km003c_lib(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyAdcData>()?;
    m.add_class::<PySampleRate>()?;
    m.add_class::<PyPacket>()?;
    m.add_function(wrap_pyfunction!(parse_raw_adc_data, m)?)?;
    m.add_function(wrap_pyfunction!(parse_packet, m)?)?;
    m.add_function(wrap_pyfunction!(get_sample_rates, m)?)?;
    
    // Add constants
    m.add("VID", crate::device::VID)?;
    m.add("PID", crate::device::PID)?;
    
    
    Ok(())
}