//! # One-Time Password (OTP)
//!
//! Implementation of HMAC-Based One-Time Passwords (HOTP, [RFC 4226])
//! and Time-Based One-Time Passwords (TOTP, [RFC 6238]).
//!
//! [RFC 4226]: https://tools.ietf.org/html/rfc4226
//! [RFC 6238]: https://tools.ietf.org/html/rfc6238

use core::{
    fmt,
    hint::{
        assert_unchecked,
        unreachable_unchecked,
    },
    num::NonZeroU64,
};

use hmac::{
    Hmac,
    KeyInit as _,
    Mac as _,
};
use sha1::Sha1;
use sha2::{
    Sha256,
    Sha512,
};
use subtle::ConstantTimeEq as _;

/// Supported hashing algorithms for TOTP/HOTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// SHA-1 (typically used by legacy authenticators).
    Sha1,
    /// SHA-256 (recommended for new applications).
    Sha256,
    /// SHA-512 (provides highest security margin).
    Sha512,
}

/// Potential errors that can occur during TOTP/HOTP generation or validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The time step cannot be zero.
    ZeroStep,
    /// Digits must be between 1 and 10.
    InvalidDigits,
    /// The secret key length is invalid for the chosen algorithm.
    InvalidSecret,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            | Error::ZeroStep => write!(f, "Time step cannot be zero"),
            | Error::InvalidDigits => write!(f, "Digits must be between 1 and 10"),
            | Error::InvalidSecret => write!(f, "Invalid secret key length"),
        }
    }
}

impl core::error::Error for Error {}

/// Configuration for HMAC-based One-Time Password (HOTP).
#[derive(Debug, Clone)]
pub struct Hotp<'a> {
    secret:    &'a [u8],
    algorithm: Algorithm,
    digits:    u8,
}

impl<'a> Hotp<'a> {
    /// Creates a new HOTP configuration.
    ///
    /// # Arguments
    /// * `secret` - The raw byte array of the shared secret.
    /// * `algorithm` - The HMAC hashing algorithm.
    /// * `digits` - Length of the output token (typically 6 or 8).
    ///
    /// # Errors
    /// Returns `Error::InvalidDigits` if `digits` is 0 or greater than 10.
    pub fn new<'s: 'a>(secret: &'s impl AsRef<[u8]>, algorithm: Algorithm, digits: u8) -> Result<Self, Error> {
        let secret = secret.as_ref();

        if digits == 0 || digits > 10 {
            return Err(Error::InvalidDigits);
        }

        Ok(Self {
            secret,
            algorithm,
            digits,
        })
    }

    /// Returns the shared secret.
    #[must_use]
    pub fn secret(&self) -> &'a [u8] {
        self.secret
    }

    /// Returns the hashing algorithm.
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Returns the number of digits in the output token.
    #[must_use]
    pub fn digits(&self) -> u8 {
        self.digits
    }

    /// Implements the core HOTP generation algorithm (RFC 4226).
    ///
    /// # Errors
    /// Returns `Error::InvalidSecret` if the internal HMAC implementation
    /// rejects the secret length.
    #[must_use]
    pub fn generate(&self, counter: u64) -> Result<String, Error> {
        // SAFETY: The constructor guarantees that `digits` is between 1 and 10.
        unsafe {
            assert_unchecked(self.digits > 0 && self.digits <= 10);
        }

        let counter_bytes = counter.to_be_bytes();
        let mut p = [0u8; 4];

        // RFC 4226 Section 5.3: Step 1 (Generate an HMAC value) and Step 2 (Generate a
        // 4-byte string).
        match self.algorithm {
            | Algorithm::Sha1 => {
                let mut mac = Hmac::<Sha1>::new_from_slice(self.secret).map_err(|_| Error::InvalidSecret)?;
                mac.update(&counter_bytes);
                let result = mac.finalize().into_bytes();

                // RFC 4226 Section 5.4: Offset extraction (lower 4 bits of the last MAC byte).
                let offset = usize::from(result[19] & 0x0F);

                let Some(slice) = result.get(offset .. offset + 4) else {
                    // SAFETY: `offset` is bounded to 0..=15 via bitwise AND.
                    // The slice range is at most 15..19, which is strictly within the 20-byte SHA-1
                    // output.
                    unsafe { unreachable_unchecked() }
                };
                p.copy_from_slice(slice);
            },
            | Algorithm::Sha256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(self.secret).map_err(|_| Error::InvalidSecret)?;
                mac.update(&counter_bytes);
                let result = mac.finalize().into_bytes();

                // RFC 4226 Section 5.4: Offset extraction (lower 4 bits of the last MAC byte).
                let offset = usize::from(result[31] & 0x0F);

                let Some(slice) = result.get(offset .. offset + 4) else {
                    // SAFETY: `offset` is bounded to 0..=15 via bitwise AND.
                    // The slice range is at most 15..19, which is strictly within the 32-byte
                    // SHA-256 output.
                    unsafe { unreachable_unchecked() }
                };
                p.copy_from_slice(slice);
            },
            | Algorithm::Sha512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(self.secret).map_err(|_| Error::InvalidSecret)?;
                mac.update(&counter_bytes);
                let result = mac.finalize().into_bytes();

                // RFC 4226 Section 5.4: Offset extraction (lower 4 bits of the last MAC byte).
                let offset = usize::from(result[63] & 0x0F);

                let Some(slice) = result.get(offset .. offset + 4) else {
                    // SAFETY: `offset` is bounded to 0..=15 via bitwise AND.
                    // The slice range is at most 15..19, which is strictly within the 64-byte
                    // SHA-512 output.
                    unsafe { unreachable_unchecked() }
                };
                p.copy_from_slice(slice);
            },
        };

        // RFC 4226 Section 5.3: Step 3 (Compute an HOTP value).
        // RFC 4226 Section 5.4: Example of returning the dynamic binary code.
        let binary_code =
            (u32::from(p[0] & 0x7F)) << 24 | u32::from(p[1]) << 16 | u32::from(p[2]) << 8 | u32::from(p[3]);

        let modulo = 10_u64.pow(u32::from(self.digits));
        let final_code = u64::from(binary_code).rem_euclid(modulo);

        Ok(format!("{:0width$}", final_code, width = self.digits as usize))
    }

    /// Verifies a user-provided token against a specific counter.
    ///
    /// # Errors
    /// Returns `Error::InvalidSecret` if the internal HMAC implementation
    /// rejects the secret length.
    #[must_use]
    pub fn verify(&self, code: &str, counter: u64) -> Result<bool, Error> {
        // SAFETY: The constructor guarantees that `digits` is between 1 and 10.
        unsafe {
            assert_unchecked(self.digits > 0 && self.digits <= 10);
        }

        if code.len() != self.digits as usize {
            return Ok(false);
        }

        let expected_code = self.generate(counter)?;
        Ok(bool::from(expected_code.as_bytes().ct_eq(code.as_bytes())))
    }
}

/// Configuration for Time-based One-Time Password (TOTP).
#[derive(Debug, Clone)]
pub struct Totp<'a> {
    hotp:         Hotp<'a>,
    step_seconds: u64,
    t0:           u64,
}

impl<'a> Totp<'a> {
    /// Creates a new TOTP configuration.
    ///
    /// # Arguments
    /// * `secret` - The raw byte array of the shared secret.
    /// * `algorithm` - The HMAC hashing algorithm.
    /// * `digits` - Length of the output token (typically 6 or 8).
    /// * `step_seconds` - The time step window (typically 30).
    /// * `t0` - The Unix epoch start (typically 0).
    ///
    /// # Errors
    /// Returns `Error::InvalidDigits` if `digits` is 0 or greater than 10.
    #[must_use]
    pub fn new<'s: 'a>(
        secret: &'s impl AsRef<[u8]>,
        algorithm: Algorithm,
        digits: u8,
        step_seconds: NonZeroU64,
        t0: u64,
    ) -> Result<Self, Error> {
        Ok(Self {
            hotp: Hotp::new(secret, algorithm, digits)?,
            step_seconds: step_seconds.get(),
            t0,
        })
    }

    /// Returns the shared secret.
    #[must_use]
    pub fn secret(&self) -> &'a [u8] {
        self.hotp.secret()
    }

    /// Returns the hashing algorithm.
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        self.hotp.algorithm()
    }

    /// Returns the number of digits in the output token.
    #[must_use]
    pub fn digits(&self) -> u8 {
        self.hotp.digits()
    }

    /// Returns the time step window in seconds.
    #[must_use]
    pub fn step_seconds(&self) -> u64 {
        self.step_seconds
    }

    /// Returns the Unix epoch start.
    #[must_use]
    pub fn t0(&self) -> u64 {
        self.t0
    }

    /// Generates a TOTP code for a specific Unix timestamp.
    ///
    /// # Errors
    /// Returns `Error::InvalidSecret` if the internal HMAC implementation
    /// rejects the secret length.
    #[must_use]
    pub fn generate(&self, unix_time_sec: u64) -> Result<String, Error> {
        let step = self.calculate_step(unix_time_sec);
        self.hotp.generate(step)
    }

    /// Verifies a user-provided token against a specific timestamp, allowing
    /// for clock skew.
    ///
    /// # Arguments
    /// * `code` - The user-provided token string.
    /// * `unix_time_sec` - The current epoch time in seconds.
    /// * `skew_tolerance` - The number of time steps before and after the
    ///   current step to check.
    ///
    /// # Errors
    /// Returns `Error::InvalidSecret` if the internal HMAC implementation
    /// rejects the secret length.
    #[must_use]
    pub fn verify(&self, code: &str, unix_time_sec: u64, skew_tolerance: u64) -> Result<bool, Error> {
        // SAFETY: The constructor guarantees that `digits` is between 1 and 10.
        unsafe {
            assert_unchecked(self.hotp.digits > 0 && self.hotp.digits <= 10);
        }

        if code.len() != self.hotp.digits as usize {
            return Ok(false);
        }

        let current_step = self.calculate_step(unix_time_sec);
        let mut is_valid = false;

        let start_step = current_step.saturating_sub(skew_tolerance);
        let end_step = current_step.saturating_add(skew_tolerance);

        for step in start_step ..= end_step {
            let expected_code = self.hotp.generate(step)?;
            let eq_result = expected_code.as_bytes().ct_eq(code.as_bytes());
            is_valid |= bool::from(eq_result);
        }

        Ok(is_valid)
    }

    /// Converts a continuous Unix timestamp into a discrete time step counter.
    #[must_use]
    fn calculate_step(&self, unix_time: u64) -> u64 {
        // SAFETY: `step_seconds` is sourced from a `NonZeroU64` in the constructor,
        // preventing division by zero.
        unsafe {
            assert_unchecked(self.step_seconds > 0);
        }

        // RFC 6238 Section 4.2: T = (Current Unix time - T0) / X
        if unix_time < self.t0 {
            0
        } else {
            unix_time.saturating_sub(self.t0) / self.step_seconds
        }
    }
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU64;

    use super::*;

    #[test]
    fn rfc4226_hotp_tests() -> Result<(), Error> {
        let secret = b"12345678901234567890";
        let hotp = Hotp::new(secret, Algorithm::Sha1, 6)?;

        assert_eq!(hotp.secret(), secret);
        assert_eq!(hotp.algorithm(), Algorithm::Sha1);
        assert_eq!(hotp.digits(), 6);

        let expected_results = [
            (0, "755224"),
            (1, "287082"),
            (2, "359152"),
            (3, "969429"),
            (4, "338314"),
            (5, "254676"),
            (6, "287922"),
            (7, "162583"),
            (8, "399871"),
            (9, "520489"),
        ];

        for (count, expected) in expected_results {
            assert_eq!(hotp.generate(count)?, expected, "HOTP mismatch at count {}", count);
            assert!(hotp.verify(expected, count)?, "Verification failed at count {}", count);
        }

        Ok(())
    }

    #[test]
    fn rfc6238_totp_tests_sha1() -> Result<(), Error> {
        let secret: &[u8; 20] = b"12345678901234567890";
        let step = NonZeroU64::new(30).ok_or(Error::ZeroStep)?;
        let totp = Totp::new(secret, Algorithm::Sha1, 8, step, 0)?;

        assert_eq!(totp.secret(), secret);
        assert_eq!(totp.algorithm(), Algorithm::Sha1);
        assert_eq!(totp.digits(), 8);
        assert_eq!(totp.step_seconds(), 30);
        assert_eq!(totp.t0(), 0);

        let expected_results = [
            (59, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ];

        for (time, expected) in expected_results {
            assert_eq!(
                totp.generate(time)?,
                expected,
                "TOTP SHA1 generation failed at time {}",
                time
            );
            assert!(
                totp.verify(expected, time, 0)?,
                "TOTP SHA1 verification failed at time {}",
                time
            );
        }

        Ok(())
    }

    #[test]
    fn rfc6238_totp_tests_sha256() -> Result<(), Error> {
        let secret: &[u8; 32] = b"12345678901234567890123456789012";
        let step = NonZeroU64::new(30).ok_or(Error::ZeroStep)?;
        let totp = Totp::new(secret, Algorithm::Sha256, 8, step, 0)?;

        let expected_results = [
            (59, "46119246"),
            (1111111109, "68084774"),
            (1111111111, "67062674"),
            (1234567890, "91819424"),
            (2000000000, "90698825"),
            (20000000000, "77737706"),
        ];

        for (time, expected) in expected_results {
            assert_eq!(
                totp.generate(time)?,
                expected,
                "TOTP SHA256 generation failed at time {}",
                time
            );
            assert!(
                totp.verify(expected, time, 0)?,
                "TOTP SHA256 verification failed at time {}",
                time
            );
        }

        Ok(())
    }

    #[test]
    fn rfc6238_totp_tests_sha512() -> Result<(), Error> {
        let secret: &[u8; 64] = b"1234567890123456789012345678901234567890123456789012345678901234";
        let step = NonZeroU64::new(30).ok_or(Error::ZeroStep)?;
        let totp = Totp::new(secret, Algorithm::Sha512, 8, step, 0)?;

        let expected_results = [
            (59, "90693936"),
            (1111111109, "25091201"),
            (1111111111, "99943326"),
            (1234567890, "93441116"),
            (2000000000, "38618901"),
            (20000000000, "47863826"),
        ];

        for (time, expected) in expected_results {
            assert_eq!(
                totp.generate(time)?,
                expected,
                "TOTP SHA512 generation failed at time {}",
                time
            );
            assert!(
                totp.verify(expected, time, 0)?,
                "TOTP SHA512 verification failed at time {}",
                time
            );
        }

        Ok(())
    }
}
