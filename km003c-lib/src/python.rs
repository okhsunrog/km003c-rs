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

impl From<SampleRate> for PySampleRate {
    fn from(rate: SampleRate) -> Self {
        PySampleRate {
            hz: rate.as_hz(),
            name: rate.to_string(),
        }
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
pub fn parse_packet(data: &[u8]) -> PyResult<Option<PyAdcData>> {
    let bytes = Bytes::from(data.to_vec());
    let raw_packet = RawPacket::try_from(bytes)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{}", e)))?;
    
    let packet = Packet::try_from(raw_packet)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{}", e)))?;
    
    match packet {
        Packet::SimpleAdcData(adc_data) => Ok(Some(PyAdcData::from(adc_data))),
        _ => Ok(None),
    }
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
    m.add_function(wrap_pyfunction!(parse_raw_adc_data, m)?)?;
    m.add_function(wrap_pyfunction!(parse_packet, m)?)?;
    m.add_function(wrap_pyfunction!(get_sample_rates, m)?)?;
    
    // Add constants
    m.add("VID", crate::device::VID)?;
    m.add("PID", crate::device::PID)?;
    
    
    Ok(())
}