use speedy::Readable;

#[derive(Debug, Clone, Copy, Default, Readable)]
pub struct AdcDataBasic {
    pub vbus_raw: i32,
    pub ibus_raw: i32,
    pub vbus_avg_raw: i32,
    pub ibus_avg_raw: i32,
    pub vbus_ori_avg_raw: i32,
    pub ibus_ori_avg_raw: i32,
    pub temp_raw: i16,
    pub vcc1_raw: u16,
    pub vcc2_raw: u16,
    pub vdp_raw: u16,
    pub vdm_raw: u16,
    pub internal_vdd_raw: u16,
    pub rate: u8,
}
