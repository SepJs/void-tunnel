// ============================================================
// VOID-TUNNEL :: vt-core :: padding :: distributions.rs
//
// Statistical Noise Distribution Matrix for Polymorphic Padding
//
// Supports: Uniform, Normal (Gaussian), Exponential, Bimodal
// distributions to mimic different traffic fingerprints.
//
// Author: Vladimir Unknown
// ============================================================

use rand::thread_rng;
use rand::Rng;
use rand_distr::{Distribution, Normal, Exp};
use serde::{Deserialize, Serialize};

use crate::error::{VtError, VtResult};
use crate::padding::polymorphic::{MAX_PADDING, MIN_PADDING};

/// Active statistical distribution for padding byte count selection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PaddingDistribution {
    /// Uniform random: padding ∈ [min_bytes, max_bytes]
    Uniform,

    /// Normal (Gaussian): centered at `mean`, std_dev configurable
    /// Clamped to [min_bytes, max_bytes]
    Normal,

    /// Exponential: mimics typical HTTP asset download sizes
    Exponential,

    /// Bimodal: two peaks, mimics mixed traffic (images + API calls)
    Bimodal,
}

/// Full parameter set for the active padding distribution.
/// Serializable to/from TOML config and JSON patches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaddingParams {
    /// Active distribution type
    pub distribution: PaddingDistribution,

    /// Minimum padding bytes (must be ≥ MIN_PADDING = 32)
    pub min_bytes: usize,

    /// Maximum padding bytes (must be ≤ MAX_PADDING = 1500)
    pub max_bytes: usize,

    /// Mean for Normal/Bimodal distributions (bytes)
    pub mean: Option<f64>,

    /// Standard deviation for Normal/Bimodal distributions
    pub std_dev: Option<f64>,
}

impl PaddingParams {
    /// Validate that parameters are within acceptable bounds.
    pub fn validate(&self) -> VtResult<()> {
        if self.min_bytes < MIN_PADDING {
            return Err(VtError::PaddingDistributionInvalid);
        }
        if self.max_bytes > MAX_PADDING {
            return Err(VtError::PaddingDistributionInvalid);
        }
        if self.min_bytes >= self.max_bytes {
            return Err(VtError::PaddingDistributionInvalid);
        }
        Ok(())
    }
}

impl PaddingDistribution {
    /// Sample a padding byte count from this distribution.
    pub fn sample(&self, params: &PaddingParams) -> VtResult<usize> {
        params.validate()?;
        let mut rng = thread_rng();

        let raw = match self {
            PaddingDistribution::Uniform => {
                rng.gen_range(params.min_bytes..=params.max_bytes) as f64
            }

            PaddingDistribution::Normal => {
                let mean = params.mean.unwrap_or(
                    (params.min_bytes + params.max_bytes) as f64 / 2.0,
                );
                let std_dev = params.std_dev.unwrap_or(
                    (params.max_bytes - params.min_bytes) as f64 / 6.0,
                );
                let normal = Normal::new(mean, std_dev)
                    .map_err(|_| VtError::PaddingDistributionInvalid)?;
                normal.sample(&mut rng)
            }

            PaddingDistribution::Exponential => {
                let lambda = 1.0 / (params.min_bytes as f64 * 3.0);
                let exp = Exp::new(lambda)
                    .map_err(|_| VtError::PaddingDistributionInvalid)?;
                params.min_bytes as f64 + exp.sample(&mut rng)
            }

            PaddingDistribution::Bimodal => {
                // Two Gaussian peaks: low-size (API calls) and high-size (assets)
                let low_mean = params.min_bytes as f64
                    + (params.max_bytes - params.min_bytes) as f64 * 0.2;
                let high_mean = params.min_bytes as f64
                    + (params.max_bytes - params.min_bytes) as f64 * 0.75;
                let std_dev = params.std_dev.unwrap_or(
                    (params.max_bytes - params.min_bytes) as f64 / 10.0,
                );

                // 50% chance each peak
                let mean = if rng.gen_bool(0.5) { low_mean } else { high_mean };
                let normal = Normal::new(mean, std_dev)
                    .map_err(|_| VtError::PaddingDistributionInvalid)?;
                normal.sample(&mut rng)
            }
        };

        // Clamp to valid range and convert to usize
        let clamped = raw
            .max(params.min_bytes as f64)
            .min(params.max_bytes as f64)
            .round() as usize;

        Ok(clamped)
    }
}

/// Default padding parameters optimized for Iran profile:
/// Medium uniform distribution mimicking mobile HTTPS API calls.
pub fn iran_default_params() -> PaddingParams {
    PaddingParams {
        distribution: PaddingDistribution::Uniform,
        min_bytes: 64,
        max_bytes: 512,
        mean: None,
        std_dev: None,
    }
}

/// Default padding parameters for China profile:
/// High-volume Normal distribution to mask proxy packet-length frequencies.
pub fn china_default_params() -> PaddingParams {
    PaddingParams {
        distribution: PaddingDistribution::Normal,
        min_bytes: 128,
        max_bytes: 1024,
        mean: Some(512.0),
        std_dev: Some(128.0),
    }
}

/// Default padding parameters for Russia profile:
/// Bimodal distribution to blend with mixed corporate + consumer traffic.
pub fn russia_default_params() -> PaddingParams {
    PaddingParams {
        distribution: PaddingDistribution::Bimodal,
        min_bytes: 64,
        max_bytes: 896,
        mean: None,
        std_dev: Some(64.0),
    }
}

// ── Unit Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn uniform_params() -> PaddingParams {
        PaddingParams {
            distribution: PaddingDistribution::Uniform,
            min_bytes: 32,
            max_bytes: 1500,
            mean: None,
            std_dev: None,
        }
    }

    #[test]
    fn test_uniform_sample_in_range() {
        let params = uniform_params();
        for _ in 0..100 {
            let n = params.distribution.sample(&params).unwrap();
            assert!(n >= params.min_bytes && n <= params.max_bytes);
        }
    }

    #[test]
    fn test_normal_sample_clamped() {
        let params = PaddingParams {
            distribution: PaddingDistribution::Normal,
            min_bytes: 32,
            max_bytes: 1500,
            mean: Some(256.0),
            std_dev: Some(64.0),
        };
        for _ in 0..100 {
            let n = params.distribution.sample(&params).unwrap();
            assert!(n >= 32 && n <= 1500, "Sample {} out of range", n);
        }
    }

    #[test]
    fn test_exponential_sample_in_range() {
        let params = PaddingParams {
            distribution: PaddingDistribution::Exponential,
            min_bytes: 64,
            max_bytes: 1500,
            mean: None,
            std_dev: None,
        };
        for _ in 0..100 {
            let n = params.distribution.sample(&params).unwrap();
            assert!(n >= 64 && n <= 1500);
        }
    }

    #[test]
    fn test_bimodal_sample_in_range() {
        let params = russia_default_params();
        for _ in 0..100 {
            let n = params.distribution.sample(&params).unwrap();
            assert!(n >= params.min_bytes && n <= params.max_bytes);
        }
    }

    #[test]
    fn test_invalid_params_min_too_small() {
        let params = PaddingParams {
            distribution: PaddingDistribution::Uniform,
            min_bytes: 1, // Below MIN_PADDING = 32
            max_bytes: 256,
            mean: None,
            std_dev: None,
        };
        assert!(params.validate().is_err());
    }

    #[test]
    fn test_invalid_params_max_too_large() {
        let params = PaddingParams {
            distribution: PaddingDistribution::Uniform,
            min_bytes: 32,
            max_bytes: 9999, // Above MAX_PADDING = 1500
            mean: None,
            std_dev: None,
        };
        assert!(params.validate().is_err());
    }

    #[test]
    fn test_invalid_params_min_equals_max() {
        let params = PaddingParams {
            distribution: PaddingDistribution::Uniform,
            min_bytes: 256,
            max_bytes: 256,
            mean: None,
            std_dev: None,
        };
        assert!(params.validate().is_err());
    }

    #[test]
    fn test_iran_default_params_valid() {
        assert!(iran_default_params().validate().is_ok());
    }

    #[test]
    fn test_china_default_params_valid() {
        assert!(china_default_params().validate().is_ok());
    }

    #[test]
    fn test_russia_default_params_valid() {
        assert!(russia_default_params().validate().is_ok());
    }
}