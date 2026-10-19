//! The power contract a USB PD negotiation establishes.
//!
//! [`PdContract`] follows the negotiation messages in a [`PdLogger`] stream:
//! Source_Capabilities, Request, Accept or Reject, then PS_RDY. The KM003C only
//! reports messages it saw while a host was reading it, so a contract
//! negotiated before the meter was reconnected is kept and marked as carried
//! over, until a new negotiation or a detach replaces it.
//!
//! [`PdLogger`]: crate::PdLogger

use std::fmt;

use crate::pd_log::{PdLogCategory, PdLogEntry};

/// How far the negotiation of the current contract got.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PdContractStage {
    /// No negotiation seen.
    #[default]
    None,
    /// The source advertised its capabilities.
    Offered,
    /// The sink sent a Request.
    Requested,
    /// The source accepted the request and is changing its output.
    Accepted,
    /// The source rejected the request.
    Rejected,
    /// The source reported PS_RDY: the contract is in effect.
    Active,
}

/// The contract negotiated between the source and the sink.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PdContract {
    request: Option<String>,
    stage: PdContractStage,
    carried_over: bool,
}

impl PdContract {
    /// Follow one log entry. Connect, Disconnect and Soft_Reset clear the
    /// contract; the negotiation messages advance it.
    pub fn observe(&mut self, entry: &PdLogEntry) {
        match (entry.category, entry.title.as_str()) {
            (PdLogCategory::Connect | PdLogCategory::Disconnect, _) | (_, "Soft_Reset") => *self = Self::default(),
            (PdLogCategory::Request, _) => {
                self.request = entry
                    .details
                    .first()
                    .map(|detail| detail.strip_prefix("RDO: ").unwrap_or(detail).to_string());
                self.stage = PdContractStage::Requested;
                self.carried_over = false;
            }
            (_, "Source_Capabilities" | "EPR_Source_Capabilities") => {
                *self = Self {
                    stage: PdContractStage::Offered,
                    ..Self::default()
                };
            }
            (_, "Accept") if self.stage == PdContractStage::Requested => self.stage = PdContractStage::Accepted,
            (_, "Reject") if self.stage == PdContractStage::Requested => self.stage = PdContractStage::Rejected,
            (_, "PS_RDY") if self.stage == PdContractStage::Accepted => self.stage = PdContractStage::Active,
            _ => {}
        }
    }

    /// The meter was reconnected: messages sent in the meantime were missed,
    /// so the contract may be out of date.
    pub fn device_reconnected(&mut self) {
        if self.stage != PdContractStage::None {
            self.carried_over = true;
        }
    }

    /// Follow the sink detection of a [`PdConnectionTracker`]. A detached sink
    /// ends any contract.
    ///
    /// [`PdConnectionTracker`]: crate::PdConnectionTracker
    pub fn observe_sink(&mut self, connected: Option<bool>) {
        if connected == Some(false) && self.stage != PdContractStage::None {
            *self = Self::default();
        }
    }

    pub const fn stage(&self) -> PdContractStage {
        self.stage
    }

    /// The requested power, such as `PDO#2 (Fixed 9V @ 3.0A (27W)) @ 2.2A`.
    pub fn request(&self) -> Option<&str> {
        self.request.as_deref()
    }

    /// Whether the contract was negotiated before the meter was reconnected.
    pub const fn is_carried_over(&self) -> bool {
        self.carried_over
    }
}

impl fmt::Display for PdContract {
    /// One line for display, `—` when there is no contract.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let request = self.request.as_deref().unwrap_or("request");
        match self.stage {
            PdContractStage::None => f.write_str("—")?,
            PdContractStage::Offered => f.write_str("source capabilities offered")?,
            PdContractStage::Requested => write!(f, "{request} · requested")?,
            PdContractStage::Accepted => write!(f, "{request} · accepted, waiting for PS_RDY")?,
            PdContractStage::Rejected => write!(f, "{request} · rejected")?,
            PdContractStage::Active => f.write_str(request)?,
        }
        if self.carried_over {
            f.write_str(" · seen before reconnecting")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PdLogger;
    use crate::pd::{PdEvent, PdEventData};
    use uom::si::f64::Time;
    use uom::si::time::millisecond;

    fn message(wire_hex: &str) -> PdEvent {
        PdEvent {
            timestamp: Time::new::<millisecond>(0.0),
            data: PdEventData::PdMessage {
                sop: 0,
                wire_data: hex::decode(wire_hex).unwrap(),
            },
        }
    }

    fn follow(contract: &mut PdContract, logger: &mut PdLogger, events: &[PdEvent]) {
        for event in events {
            contract.observe(&logger.log_event(event));
        }
    }

    fn negotiation() -> [PdEvent; 4] {
        [
            message("a1612c9101082cd102002cc103002cb10400454106003c21dcc0"), // Source_Capabilities
            message("8210dc700323"),                                         // Request PDO#2
            message("a305"),                                                 // Accept
            message("a607"),                                                 // PS_RDY
        ]
    }

    #[test]
    fn a_negotiation_ends_in_an_active_contract() {
        let (mut contract, mut logger) = (PdContract::default(), PdLogger::new());
        follow(&mut contract, &mut logger, &negotiation());

        assert_eq!(contract.stage(), PdContractStage::Active);
        assert_eq!(contract.to_string(), "PDO#2 (Fixed 9V @ 3.0A (27W)) @ 2.2A");
    }

    #[test]
    fn a_disconnect_clears_the_contract() {
        let (mut contract, mut logger) = (PdContract::default(), PdLogger::new());
        follow(&mut contract, &mut logger, &negotiation());
        follow(
            &mut contract,
            &mut logger,
            &[PdEvent {
                timestamp: Time::new::<millisecond>(0.0),
                data: PdEventData::Disconnect,
            }],
        );

        assert_eq!(contract.stage(), PdContractStage::None);
        assert_eq!(contract.to_string(), "—");
    }

    #[test]
    fn a_reconnect_keeps_the_contract_until_the_sink_detaches() {
        let (mut contract, mut logger) = (PdContract::default(), PdLogger::new());
        follow(&mut contract, &mut logger, &negotiation());

        contract.device_reconnected();
        assert!(contract.is_carried_over());
        assert!(contract.to_string().ends_with("· seen before reconnecting"));

        contract.observe_sink(None);
        assert_eq!(contract.stage(), PdContractStage::Active);
        contract.observe_sink(Some(false));
        assert_eq!(contract.stage(), PdContractStage::None);
    }

    #[test]
    fn a_new_request_after_reconnecting_is_current() {
        let (mut contract, mut logger) = (PdContract::default(), PdLogger::new());
        follow(&mut contract, &mut logger, &negotiation());
        contract.device_reconnected();

        let mut logger = PdLogger::new();
        follow(&mut contract, &mut logger, &negotiation());

        assert!(!contract.is_carried_over());
        assert_eq!(contract.stage(), PdContractStage::Active);
    }
}
