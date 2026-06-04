use recon_core::detectors::tls::classify_expiry;
use recon_core::Severity;

#[test]
fn expired_cert_is_critical() {
    let (sev, title, _fix) = classify_expiry(-1).expect("negative days should classify");
    assert_eq!(sev, Severity::Critical);
    assert_eq!(title, "Certificate expired");
}

#[test]
fn expiring_soon_is_high() {
    let (sev, title, _fix) = classify_expiry(10).expect("10 days should classify");
    assert_eq!(sev, Severity::High);
    assert_eq!(title, "Certificate expiring soon");
}

#[test]
fn healthy_runway_is_none() {
    assert!(classify_expiry(100).is_none());
}

#[test]
fn zero_days_is_critical() {
    // Expiring today (0 days remaining) is treated as expired → Critical.
    let (sev, _title, _fix) = classify_expiry(0).expect("0 days should classify");
    assert_eq!(sev, Severity::Critical);
}
