//! Device-type and operating-system classification.
//!
//! The scorer answers "what is this device called". This answers "what is it",
//! from the same pile of stored signals plus the vendor and a little
//! behavioural context.
//!
//! ## Precedence, and why it is ordered this way
//!
//! Every source of evidence is ranked by how hard it is to be wrong about, not
//! by how often it fires:
//!
//! 1. **A Router Advertisement.** A device that emits one is a router. There is
//!    no second reading.
//! 2. **An SSDP device URN.** The device declared its own UPnP class in a header
//!    it chose to broadcast.
//! 3. **An mDNS service type.** `_printer._tcp` is a printer. Strong, but a
//!    general-purpose computer sharing a printer also advertises it, which is
//!    why it sits below a URN.
//! 4. **A DHCP option 55 fingerprint.** Carries its own confidence from
//!    [`crate::identity::fingerprint`], exact matches ahead of near ones.
//! 5. **A DHCP vendor class or an mDNS model string.** Self-declared text, and
//!    text patterns are where false positives live.
//! 6. **The OUI vendor.** Espressif is an IoT chip and Brother makes printers,
//!    but a vendor makes many things and this is the weakest real evidence.
//! 7. **Behaviour.** A device that has been continuously present for a day and
//!    carries an IoT vendor is a fixed smart-home device rather than somebody's
//!    phone. Last, because it is inference rather than evidence.
//!
//! The winner sets `device_type` and its rank sets the stored confidence, so a
//! reader downstream can tell "this is a printer because it said so" from "this
//! is probably a printer because Brother made it".
//!
//! Operating system is scored separately over the same evidence, because a
//! device's type and its OS come from different signals: a fingerprint knows the
//! OS and a service type knows the type.

use crate::types::{MacAddr, Signal, SignalKind};

use super::fingerprint;

/// The device types Netgrasp will assign.
///
/// A closed vocabulary rather than free text, because `state.device_type_
/// overrides` keys on these and the Trovato plugin will facet on them. Anything
/// outside the list, including from a downloaded fingerprint table, is ignored
/// rather than stored.
pub const DEVICE_TYPES: [&str; 17] = [
    "router",
    "access_point",
    "printer",
    "media_player",
    "smart_speaker",
    "smart_home_device",
    "thermostat",
    "camera",
    "nas",
    "phone",
    "tablet",
    "computer",
    "game_console",
    "tv",
    "voip_phone",
    "iot_device",
    "wearable",
];

/// Confidence for a Router Advertisement, which is not really a guess.
const CONF_NDP_ROLE: f64 = 0.99;
/// Confidence for a self-declared UPnP device class.
const CONF_SSDP_URN: f64 = 0.9;
/// Confidence for an mDNS service type.
const CONF_MDNS_SERVICE: f64 = 0.85;
/// Confidence for a match on a self-declared text string.
const CONF_TEXT: f64 = 0.7;
/// Confidence for a NetBIOS presence, which says Windows-speaking machine.
const CONF_NETBIOS: f64 = 0.5;
/// Confidence for an OUI vendor hint.
const CONF_VENDOR: f64 = 0.4;
/// Confidence for a behavioural inference.
const CONF_BEHAVIOUR: f64 = 0.35;

/// How long a device must be continuously present before "always on" means
/// anything. A day covers a laptop that stayed open overnight.
pub const ALWAYS_ON_HOURS: i64 = 24;

/// Everything the classifier needs about one device.
#[derive(Debug, Clone)]
pub struct ClassifyInput<'a> {
    /// The device's hardware address, for the locally-administered check.
    pub mac: MacAddr,
    /// Every stored signal, most recently confirmed first.
    pub signals: &'a [Signal],
    /// The IEEE vendor, when the registry knows one.
    pub vendor: Option<&'a str>,
    /// True when the device has been known for at least [`ALWAYS_ON_HOURS`] and
    /// has never been seen to go offline.
    pub always_on: bool,
}

/// What the classifier concluded.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Classification {
    /// The device type, from [`DEVICE_TYPES`].
    pub device_type: Option<String>,
    /// The operating system family.
    pub os_family: Option<String>,
    /// How much to trust `device_type`.
    pub confidence: f64,
    /// Which evidence produced the device type, for the event details and for
    /// answering "why does it think that".
    pub reason: Option<String>,
}

impl Classification {
    /// True when the type or the OS changed category.
    ///
    /// A category change is one known value becoming a different known value.
    /// Learning a type for the first time is a refinement, not a change, and
    /// treating it as one would make every device fire an alert on its second
    /// packet.
    #[must_use]
    pub fn changed_category(&self, previous: &Classification) -> bool {
        changed(previous.device_type.as_deref(), self.device_type.as_deref())
            || changed(previous.os_family.as_deref(), self.os_family.as_deref())
    }

    /// True when anything about the type or OS differs, including a first
    /// classification.
    #[must_use]
    pub fn changed_at_all(&self, previous: &Classification) -> bool {
        previous.device_type != self.device_type || previous.os_family != self.os_family
    }
}

/// True when a known value became a different known value.
fn changed(before: Option<&str>, after: Option<&str>) -> bool {
    matches!((before, after), (Some(b), Some(a)) if b != a)
}

/// mDNS service types and what advertising one means.
///
/// Ordered most specific first: a device advertising both `_airplay._tcp` and
/// `_ssh._tcp` is an Apple TV that happens to accept logins, not a computer.
const MDNS_SERVICES: [(&str, &str); 26] = [
    ("_airplay._tcp", "media_player"),
    ("_raop._tcp", "media_player"),
    ("_googlecast._tcp", "media_player"),
    ("_dial._tcp", "tv"),
    ("_daap._tcp", "media_player"),
    ("_sonos._tcp", "smart_speaker"),
    ("_spotify-connect._tcp", "smart_speaker"),
    ("_printer._tcp", "printer"),
    ("_ipp._tcp", "printer"),
    ("_ipps._tcp", "printer"),
    ("_pdl-datastream._tcp", "printer"),
    ("_scanner._tcp", "printer"),
    ("_uscan._tcp", "printer"),
    ("_uscans._tcp", "printer"),
    ("_hap._tcp", "smart_home_device"),
    ("_homekit._tcp", "smart_home_device"),
    ("_matter._tcp", "smart_home_device"),
    ("_matterc._udp", "smart_home_device"),
    ("_esphomelib._tcp", "smart_home_device"),
    ("_hue._tcp", "smart_home_device"),
    ("_axis-video._tcp", "camera"),
    ("_adisk._tcp", "nas"),
    ("_afpovertcp._tcp", "nas"),
    ("_smb._tcp", "nas"),
    ("_nvstream._tcp", "game_console"),
    ("_workstation._tcp", "computer"),
];

/// Fragments of an SSDP `NT`/`ST` URN and what they mean.
const SSDP_DEVICE_TYPES: [(&str, &str); 8] = [
    ("internetgatewaydevice", "router"),
    ("wfadevice", "access_point"),
    ("mediarenderer", "media_player"),
    ("mediaserver", "nas"),
    (":printer:", "printer"),
    ("dial-multiscreen", "tv"),
    (":scanner:", "printer"),
    ("basic:1", "smart_home_device"),
];

/// Fragments of a self-declared text string and the device type they imply.
///
/// Matched case-insensitively against the DHCP vendor class, the mDNS model and
/// the SSDP `SERVER` header.
const TEXT_DEVICE_TYPES: [(&str, &str); 22] = [
    ("ipad", "tablet"),
    ("iphone", "phone"),
    ("applewatch", "wearable"),
    ("watch", "wearable"),
    ("appletv", "media_player"),
    ("macbook", "computer"),
    ("imac", "computer"),
    ("macmini", "computer"),
    ("roku", "tv"),
    ("chromecast", "media_player"),
    ("shield", "media_player"),
    ("sonos", "smart_speaker"),
    ("echo", "smart_speaker"),
    ("printer", "printer"),
    ("jetdirect", "printer"),
    ("brother", "printer"),
    ("nintendo", "game_console"),
    ("playstation", "game_console"),
    ("xbox", "game_console"),
    ("thermostat", "thermostat"),
    ("camera", "camera"),
    ("android-dhcp", "phone"),
];

/// Fragments of a self-declared text string and the OS family they imply.
const TEXT_OS: [(&str, &str); 14] = [
    ("msft 5.0", "Windows"),
    ("windows", "Windows"),
    ("android-dhcp", "Android"),
    ("android", "Android"),
    ("iphone", "iOS"),
    ("ipad", "iPadOS"),
    ("appletv", "tvOS"),
    ("applewatch", "watchOS"),
    ("macbook", "macOS"),
    ("imac", "macOS"),
    ("macmini", "macOS"),
    ("darwin", "macOS"),
    ("dhcpcd", "Linux"),
    ("linux", "Linux"),
];

/// Fragments of an IEEE vendor name and the device type they imply.
///
/// Every one of these is a vendor that makes essentially one kind of thing. A
/// vendor with a broad catalogue is deliberately absent: guessing "Samsung
/// therefore television" is wrong about as often as it is right.
const VENDOR_DEVICE_TYPES: [(&str, &str); 22] = [
    ("espressif", "iot_device"),
    ("tuya", "smart_home_device"),
    ("shelly", "smart_home_device"),
    ("signify", "smart_home_device"),
    ("philips lighting", "smart_home_device"),
    ("nest labs", "thermostat"),
    ("ecobee", "thermostat"),
    ("sonos", "smart_speaker"),
    ("roku", "tv"),
    ("brother", "printer"),
    ("lexmark", "printer"),
    ("zebra tech", "printer"),
    ("axis communications", "camera"),
    ("hikvision", "camera"),
    ("dahua", "camera"),
    ("reolink", "camera"),
    ("synology", "nas"),
    ("qnap", "nas"),
    ("nintendo", "game_console"),
    ("sony interactive", "game_console"),
    ("yealink", "voip_phone"),
    ("grandstream", "voip_phone"),
];

/// Vendor fragments whose devices are always-on fixtures rather than something
/// somebody carries.
const IOT_VENDORS: [&str; 8] = [
    "espressif",
    "tuya",
    "shelly",
    "signify",
    "philips lighting",
    "sonoff",
    "itead",
    "broadlink",
];

/// Classifies a device.
#[must_use]
pub fn classify(input: &ClassifyInput<'_>) -> Classification {
    let mut out = Classification::default();

    // Device type, strongest evidence first. The first hit wins outright rather
    // than voting, because a weaker source agreeing adds nothing and a weaker
    // source disagreeing is exactly the case the ordering exists to settle.
    for (device_type, confidence, reason) in device_type_candidates(input) {
        if is_known_type(&device_type) {
            out.device_type = Some(device_type);
            out.confidence = confidence;
            out.reason = Some(reason);
            break;
        }
    }

    out.os_family = os_family(input);
    out
}

/// Every device-type candidate the evidence supports, strongest first.
fn device_type_candidates(input: &ClassifyInput<'_>) -> Vec<(String, f64, String)> {
    let mut out = Vec::new();

    if values(input.signals, SignalKind::NdpRole)
        .any(|v| v.eq_ignore_ascii_case(crate::capture::ndp::ROLE_ROUTER))
    {
        out.push((
            "router".to_string(),
            CONF_NDP_ROLE,
            "router advertisement".to_string(),
        ));
    }

    for urn in values(input.signals, SignalKind::SsdpDeviceType) {
        let lower = urn.to_ascii_lowercase();
        if let Some((_, device_type)) = SSDP_DEVICE_TYPES
            .iter()
            .find(|(fragment, _)| lower.contains(fragment))
        {
            out.push((
                (*device_type).to_string(),
                CONF_SSDP_URN,
                format!("SSDP device type {urn}"),
            ));
        }
    }

    for service in values(input.signals, SignalKind::MdnsService) {
        let lower = service.to_ascii_lowercase();
        if let Some((_, device_type)) = MDNS_SERVICES
            .iter()
            .find(|(name, _)| lower.starts_with(name))
        {
            out.push((
                (*device_type).to_string(),
                CONF_MDNS_SERVICE,
                format!("mDNS service {service}"),
            ));
        }
    }

    for list in values(input.signals, SignalKind::DhcpFingerprint) {
        if let Some(found) = fingerprint::db().lookup(list)
            && let Some(device_type) = &found.class.device_type
        {
            out.push((
                device_type.clone(),
                found.confidence,
                format!(
                    "DHCP fingerprint {} ({})",
                    found.class.description,
                    if found.exact { "exact" } else { "nearest" }
                ),
            ));
        }
    }

    for (kind, label) in [
        (SignalKind::DhcpVendorClass, "DHCP vendor class"),
        (SignalKind::MdnsModel, "mDNS model"),
        (SignalKind::SsdpServer, "SSDP server"),
    ] {
        for text in values(input.signals, kind) {
            if let Some(device_type) = match_fragment(text, &TEXT_DEVICE_TYPES) {
                out.push((
                    device_type.to_string(),
                    CONF_TEXT,
                    format!("{label} {text}"),
                ));
            }
        }
    }

    // A machine speaking NetBIOS is a general-purpose computer. A NAS running
    // Samba also speaks it, which is why this sits below every self-declared
    // signal and why a NAS that advertises `_smb._tcp` over mDNS is classified
    // by that instead.
    if values(input.signals, SignalKind::NetbiosName)
        .next()
        .is_some()
    {
        out.push((
            "computer".to_string(),
            CONF_NETBIOS,
            "NetBIOS name service".to_string(),
        ));
    }

    if let Some(vendor) = input.vendor {
        if let Some(device_type) = match_fragment(vendor, &VENDOR_DEVICE_TYPES) {
            out.push((
                device_type.to_string(),
                CONF_VENDOR,
                format!("vendor {vendor}"),
            ));
        }
        // Behavioural: an IoT chip that never leaves is a fixture on the wall,
        // not a gadget in a pocket.
        if input.always_on && IOT_VENDORS.iter().any(|v| contains_fragment(vendor, v)) {
            out.push((
                "smart_home_device".to_string(),
                CONF_BEHAVIOUR,
                format!("always on with IoT vendor {vendor}"),
            ));
        }
    }

    out
}

/// Picks an operating system family.
fn os_family(input: &ClassifyInput<'_>) -> Option<String> {
    for list in values(input.signals, SignalKind::DhcpFingerprint) {
        if let Some(found) = fingerprint::db().lookup(list)
            && let Some(os) = &found.class.os_family
        {
            return Some(os.clone());
        }
    }
    for kind in [
        SignalKind::MdnsModel,
        SignalKind::DhcpVendorClass,
        SignalKind::SsdpServer,
    ] {
        for text in values(input.signals, kind) {
            if let Some(os) = match_fragment(text, &TEXT_OS) {
                return Some(os.to_string());
            }
        }
    }
    // A workgroup is a Windows networking concept, but Samba speaks it too, so
    // this is the last thing consulted and never overrides a fingerprint.
    if values(input.signals, SignalKind::NetbiosWorkgroup)
        .next()
        .is_some()
    {
        return Some("Windows".to_string());
    }
    None
}

/// Values of one signal kind, most recently confirmed first, blanks skipped.
fn values(signals: &[Signal], kind: SignalKind) -> impl Iterator<Item = &str> {
    signals
        .iter()
        .filter(move |s| s.kind == kind)
        .map(|s| s.value.trim())
        .filter(|v| !v.is_empty())
}

/// First table entry whose fragment appears in the text, case-insensitively.
fn match_fragment<'t>(text: &str, table: &'t [(&'t str, &'t str)]) -> Option<&'t str> {
    let lower = text.to_ascii_lowercase();
    table
        .iter()
        .find(|(fragment, _)| lower.contains(fragment))
        .map(|(_, value)| *value)
}

/// Case-insensitive substring test.
fn contains_fragment(text: &str, fragment: &str) -> bool {
    text.to_ascii_lowercase().contains(fragment)
}

/// True for a device type in the closed vocabulary.
#[must_use]
pub fn is_known_type(device_type: &str) -> bool {
    DEVICE_TYPES.contains(&device_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac() -> MacAddr {
        "3c:22:fb:01:02:03".parse().expect("test mac")
    }

    fn classify_with(signals: &[Signal], vendor: Option<&str>) -> Classification {
        classify(&ClassifyInput {
            mac: mac(),
            signals,
            vendor,
            always_on: false,
        })
    }

    fn signal(kind: SignalKind, value: &str) -> Signal {
        Signal::new(kind, value)
    }

    #[test]
    fn nothing_known_classifies_as_nothing() {
        let out = classify_with(&[], None);
        assert_eq!(out.device_type, None);
        assert_eq!(out.os_family, None);
        assert_eq!(out.confidence, 0.0);
    }

    #[test]
    fn an_mdns_service_type_names_the_device_type() {
        let out = classify_with(&[signal(SignalKind::MdnsService, "_ipp._tcp")], None);
        assert_eq!(out.device_type.as_deref(), Some("printer"));
        assert_eq!(out.confidence, CONF_MDNS_SERVICE);
        assert!(out.reason.expect("reason").contains("_ipp._tcp"));
    }

    #[test]
    fn a_router_advertisement_beats_every_other_reading() {
        // A router that also serves media over UPnP is still a router.
        let out = classify_with(
            &[
                signal(SignalKind::MdnsService, "_smb._tcp"),
                signal(
                    SignalKind::SsdpDeviceType,
                    "urn:schemas-upnp-org:device:MediaServer:1",
                ),
                signal(SignalKind::NdpRole, "router"),
            ],
            Some("Synology Incorporated"),
        );
        assert_eq!(out.device_type.as_deref(), Some("router"));
        assert_eq!(out.confidence, CONF_NDP_ROLE);
    }

    #[test]
    fn a_declared_upnp_class_beats_an_mdns_service() {
        let out = classify_with(
            &[
                signal(SignalKind::MdnsService, "_smb._tcp"),
                signal(
                    SignalKind::SsdpDeviceType,
                    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
                ),
            ],
            None,
        );
        assert_eq!(out.device_type.as_deref(), Some("router"));
    }

    #[test]
    fn a_vendor_is_the_weakest_reading_and_loses_to_a_service() {
        let out = classify_with(
            &[signal(SignalKind::MdnsService, "_airplay._tcp")],
            Some("Synology Incorporated"),
        );
        assert_eq!(
            out.device_type.as_deref(),
            Some("media_player"),
            "what it advertises beats what its chip vendor usually makes"
        );
    }

    #[test]
    fn a_vendor_alone_still_says_something() {
        let out = classify_with(&[], Some("Espressif Inc."));
        assert_eq!(out.device_type.as_deref(), Some("iot_device"));
        assert_eq!(out.confidence, CONF_VENDOR);
    }

    #[test]
    fn a_dhcp_fingerprint_sets_both_the_os_and_the_type() {
        let out = classify_with(
            &[signal(
                SignalKind::DhcpFingerprint,
                "1,3,6,15,31,33,43,44,46,47,119,121,249,252",
            )],
            None,
        );
        assert_eq!(out.os_family.as_deref(), Some("Windows"));
        assert_eq!(out.device_type.as_deref(), Some("computer"));
        assert_eq!(out.confidence, fingerprint::EXACT_CONFIDENCE);
    }

    #[test]
    fn a_fingerprint_that_only_knows_the_os_leaves_the_type_to_others() {
        // The iOS class implies an OS but no device type, so the type has to
        // come from somewhere else.
        let out = classify_with(
            &[
                signal(SignalKind::DhcpFingerprint, "1,121,3,6,15,119,252"),
                signal(SignalKind::DhcpVendorClass, "iPhone-iOS17.4"),
            ],
            None,
        );
        assert_eq!(out.os_family.as_deref(), Some("iOS"));
        assert_eq!(out.device_type.as_deref(), Some("phone"));
        assert_eq!(out.confidence, CONF_TEXT);
    }

    #[test]
    fn an_mdns_model_names_the_operating_system() {
        let out = classify_with(&[signal(SignalKind::MdnsModel, "MacBookPro18,1")], None);
        assert_eq!(out.os_family.as_deref(), Some("macOS"));
        assert_eq!(out.device_type.as_deref(), Some("computer"));
    }

    #[test]
    fn netbios_says_windows_speaking_machine_but_quietly() {
        let out = classify_with(
            &[
                signal(SignalKind::NetbiosName, "JEREMY-PC"),
                signal(SignalKind::NetbiosWorkgroup, "WORKGROUP"),
            ],
            None,
        );
        assert_eq!(out.device_type.as_deref(), Some("computer"));
        assert_eq!(out.os_family.as_deref(), Some("Windows"));
        assert_eq!(out.confidence, CONF_NETBIOS);
    }

    #[test]
    fn a_samba_nas_is_a_nas_not_a_windows_computer() {
        // The regression this ordering exists to prevent: a NAS speaks NetBIOS
        // and advertises _smb._tcp, and the mDNS service has to win.
        let out = classify_with(
            &[
                signal(SignalKind::MdnsService, "_smb._tcp"),
                signal(SignalKind::NetbiosName, "DISKSTATION"),
            ],
            Some("Synology Incorporated"),
        );
        assert_eq!(out.device_type.as_deref(), Some("nas"));
    }

    #[test]
    fn an_always_on_iot_vendor_becomes_a_fixture() {
        let signals = [];
        let out = classify(&ClassifyInput {
            mac: mac(),
            signals: &signals,
            vendor: Some("Shelly Europe Ltd."),
            always_on: true,
        });
        // The vendor hint outranks the behavioural one and both agree closely
        // enough; what matters is that the device is classified at all.
        assert_eq!(out.device_type.as_deref(), Some("smart_home_device"));
    }

    #[test]
    fn a_type_outside_the_vocabulary_is_never_stored() {
        // A downloaded fingerprint table could name anything; the closed
        // vocabulary is what stops it reaching the database.
        assert!(!is_known_type("toaster"));
        for known in DEVICE_TYPES {
            assert!(is_known_type(known), "{known}");
        }
    }

    #[test]
    fn a_first_classification_is_a_refinement_not_a_change() {
        let before = Classification::default();
        let after = Classification {
            device_type: Some("printer".into()),
            os_family: None,
            confidence: 0.85,
            reason: None,
        };
        assert!(
            !after.changed_category(&before),
            "learning a type is not a device changing identity"
        );
        assert!(after.changed_at_all(&before));
    }

    #[test]
    fn one_known_type_becoming_another_is_a_category_change() {
        let before = Classification {
            device_type: Some("printer".into()),
            os_family: Some("embedded".into()),
            confidence: 0.85,
            reason: None,
        };
        let after = Classification {
            device_type: Some("computer".into()),
            ..before.clone()
        };
        assert!(after.changed_category(&before));

        let os_only = Classification {
            os_family: Some("Windows".into()),
            ..before.clone()
        };
        assert!(os_only.changed_category(&before), "an OS swap counts too");
        assert!(!before.changed_category(&before), "nothing changed");
    }

    #[test]
    fn every_table_entry_names_a_type_in_the_vocabulary() {
        // A typo in one of these tables would silently disable that entry,
        // because classify() drops anything outside the vocabulary.
        for (fragment, device_type) in MDNS_SERVICES
            .iter()
            .chain(SSDP_DEVICE_TYPES.iter())
            .chain(TEXT_DEVICE_TYPES.iter())
            .chain(VENDOR_DEVICE_TYPES.iter())
        {
            assert!(
                is_known_type(device_type),
                "{fragment} maps to {device_type}, which is not a known device type"
            );
        }
    }

    #[test]
    fn every_embedded_fingerprint_device_type_is_in_the_vocabulary() {
        let db = fingerprint::db();
        for list in ["1,3,6,15,31,33,43,44,46,47,119,121,249,252", "1,3,28,6"] {
            if let Some(found) = db.lookup(list)
                && let Some(device_type) = &found.class.device_type
            {
                assert!(is_known_type(device_type), "{device_type}");
            }
        }
    }
}
