use speedy::{Readable, Writable};
use std::fmt;
use strum_macros::Display;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Writable, Readable, Display, Default)]
#[speedy(tag_type = u8)]
pub enum SampleRate {
    #[default]
    #[strum(to_string = "1 SPS")]
    Sps1 = 0,
    #[strum(to_string = "10 SPS")]
    Sps10 = 1,
    #[strum(to_string = "50 SPS")]
    Sps50 = 2,
    #[strum(to_string = "1 kSPS")]
    Sps1000 = 3,
    #[strum(to_string = "10 kSPS")]
    Sps10000 = 4,
}

impl SampleRate {
    /// Get the sample rate in samples per second
    pub fn as_hz(&self) -> u32 {
        match self {
            SampleRate::Sps1 => 1,
            SampleRate::Sps10 => 10,
            SampleRate::Sps50 => 50,
            SampleRate::Sps1000 => 1000,
            SampleRate::Sps10000 => 10000,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Readable, Writable)]
pub struct AdcDataRaw {
    pub vbus_uv: i32,           // Microvolts (µV)
    pub ibus_ua: i32,           // Microamps (µA)
    pub vbus_avg_uv: i32,       // Microvolts (µV)
    pub ibus_avg_ua: i32,       // Microamps (µA)
    pub vbus_ori_avg_raw: i32,  // Uncalibrated
    pub ibus_ori_avg_raw: i32,  // Uncalibrated
    pub temp_raw: i16,          // Celsius * 100
    pub vcc1_tenth_mv: u16,     // 0.1 millivolts
    pub vcc2_raw: u16,          // 0.1 millivolts
    pub vdp_mv: u16,            // 0.1 millivolts
    pub vdm_mv: u16,            // 0.1 millivolts
    pub internal_vdd_raw: u16,  // Internal VDD
    pub rate_raw: u8,           // Sample rate index
    pub reserved: u8,           // Reserved/padding
    pub vcc2_avg_raw: u16,      // 0.1 millivolts
    pub vdp_avg_mv: u16,        // 0.1 millivolts
    pub vdm_avg_mv: u16,        // 0.1 millivolts
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AdcDataSimple {
    // Main measurements
    pub vbus_v: f64,            // Voltage in Volts
    pub ibus_a: f64,            // Current in Amperes
    pub power_w: f64,           // Power in Watts
    
    // Averaged measurements
    pub vbus_avg_v: f64,        // Average voltage in Volts
    pub ibus_avg_a: f64,        // Average current in Amperes
    
    // Temperature
    pub temp_c: f64,            // Temperature in Celsius
    
    // USB data lines
    pub vdp_v: f64,             // D+ voltage in Volts
    pub vdm_v: f64,             // D- voltage in Volts
    pub vdp_avg_v: f64,         // Average D+ voltage in Volts
    pub vdm_avg_v: f64,         // Average D- voltage in Volts
    
    // USB CC lines
    pub cc1_v: f64,             // CC1 voltage in Volts
    pub cc2_v: f64,             // CC2 voltage in Volts
    pub cc2_avg_v: f64,         // Average CC2 voltage in Volts
    
    // Internal voltage
    pub internal_vdd_v: f64,    // Internal VDD in Volts
    
    // Sample rate
    pub sample_rate: SampleRate, // Sample rate as enum
}

impl From<AdcDataRaw> for AdcDataSimple {
    fn from(raw: AdcDataRaw) -> Self {
        // Convert voltage from µV to V
        let vbus_v = raw.vbus_uv as f64 / 1_000_000.0;
        let ibus_a = raw.ibus_ua as f64 / 1_000_000.0;
        let power_w = vbus_v * ibus_a;

        let vbus_avg_v = raw.vbus_avg_uv as f64 / 1_000_000.0;
        let ibus_avg_a = raw.ibus_avg_ua as f64 / 1_000_000.0;

        // Convert temperature from 1/100 °C to °C
        let temp_c = raw.temp_raw as f64 / 100.0;

        // Convert from 0.1mV to V (divide by 10,000)
        let vdp_v = raw.vdp_mv as f64 / 10_000.0;
        let vdm_v = raw.vdm_mv as f64 / 10_000.0;
        let vdp_avg_v = raw.vdp_avg_mv as f64 / 10_000.0;
        let vdm_avg_v = raw.vdm_avg_mv as f64 / 10_000.0;

        // CC lines also use the 0.1mV unit
        let cc1_v = raw.vcc1_tenth_mv as f64 / 10_000.0;
        let cc2_v = raw.vcc2_raw as f64 / 10_000.0;
        let cc2_avg_v = raw.vcc2_avg_raw as f64 / 10_000.0;
        
        // Internal VDD also uses 0.1mV
        let internal_vdd_v = raw.internal_vdd_raw as f64 / 10_000.0;

        // Convert raw sample rate to enum
        let sample_rate = unsafe { std::mem::transmute(raw.rate_raw) };

        AdcDataSimple {
            vbus_v,
            ibus_a,
            power_w,
            vbus_avg_v,
            ibus_avg_a,
            temp_c,
            vdp_v,
            vdm_v,
            vdp_avg_v,
            vdm_avg_v,
            cc1_v,
            cc2_v,
            cc2_avg_v,
            internal_vdd_v,
            sample_rate,
        }
    }
}

impl From<AdcDataSimple> for AdcDataRaw {
    fn from(data: AdcDataSimple) -> Self {
        AdcDataRaw {
            vbus_uv: (data.vbus_v * 1_000_000.0) as i32,
            ibus_ua: (data.ibus_a * 1_000_000.0) as i32,
            vbus_avg_uv: (data.vbus_avg_v * 1_000_000.0) as i32,
            ibus_avg_ua: (data.ibus_avg_a * 1_000_000.0) as i32,
            vbus_ori_avg_raw: 0, // We don't have this information
            ibus_ori_avg_raw: 0, // We don't have this information
            temp_raw: (data.temp_c * 100.0) as i16,
            vcc1_tenth_mv: (data.cc1_v * 10_000.0) as u16,
            vcc2_raw: (data.cc2_v * 10_000.0) as u16,
            vdp_mv: (data.vdp_v * 10_000.0) as u16,
            vdm_mv: (data.vdm_v * 10_000.0) as u16,
            internal_vdd_raw: (data.internal_vdd_v * 10_000.0) as u16,
            rate_raw: data.sample_rate as u8,
            reserved: 0,
            vcc2_avg_raw: (data.cc2_avg_v * 10_000.0) as u16,
            vdp_avg_mv: (data.vdp_avg_v * 10_000.0) as u16,
            vdm_avg_mv: (data.vdm_avg_v * 10_000.0) as u16,
        }
    }
}

impl fmt::Display for AdcDataSimple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VBUS: {:.3} V, IBUS: {:.3} A, Power: {:.3} W, Temp: {:.1} °C, Rate: {}",
            self.vbus_v, self.ibus_a, self.power_w, self.temp_c, self.sample_rate)
    }
}
