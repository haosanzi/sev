// SPDX-License-Identifier: Apache-2.0

//! For operating on SEV certificates.

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
#[repr(C, packed)]
#[allow(missing_docs)]
pub struct AttestationReport {
    pub monce: [u8; 16],
    pub launch_digest: [u8; 32],
    pub policy: u32,
    pub sig_usage: u32,
    pub sig_algo: u32,
    pub reserved: u32,
    #[serde(with = "BigArray")]
    pub sig1: [u8; 144],
}

impl Default for AttestationReport {
    #[inline]
    fn default() -> AttestationReport {
        AttestationReport {
            monce: [0; 16],
            launch_digest: [0; 32],
            policy: 0,
            sig_usage: 0,
            sig_algo: 0,
            reserved: 0,
            sig1: [0; 144],
        }
    }
}
