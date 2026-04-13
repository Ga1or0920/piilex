/// PCI-DSS requirement descriptions for report generation.
pub struct PciDssRequirement {
    pub requirement: &'static str,
    pub title: &'static str,
    pub description: &'static str,
}

pub fn requirements() -> Vec<PciDssRequirement> {
    vec![
        PciDssRequirement {
            requirement: "Req 3.2",
            title: "Do Not Store Sensitive Authentication Data After Authorization",
            description: "Do not store sensitive authentication data after authorization (even if encrypted). Sensitive authentication data includes full track data, card verification codes/values, and PINs/PIN blocks.",
        },
        PciDssRequirement {
            requirement: "Req 3.3",
            title: "Mask PAN When Displayed",
            description: "Mask PAN when displayed (the first six and last four digits are the maximum number of digits to be displayed), such that only personnel with a legitimate business need can see more than the first six/last four digits of the PAN.",
        },
        PciDssRequirement {
            requirement: "Req 3.4",
            title: "Render PAN Unreadable Anywhere It Is Stored",
            description: "Render PAN unreadable anywhere it is stored by using any of the following approaches: one-way hashes, truncation, index tokens, or strong cryptography with associated key-management processes.",
        },
        PciDssRequirement {
            requirement: "Req 3.5",
            title: "Document and Implement Procedures to Protect Keys",
            description: "Document and implement procedures to protect keys used to secure stored cardholder data against disclosure and misuse.",
        },
        PciDssRequirement {
            requirement: "Req 4.1",
            title: "Use Strong Cryptography to Safeguard Cardholder Data During Transmission",
            description: "Use strong cryptography and security protocols to safeguard sensitive cardholder data during transmission over open, public networks, including TLS 1.2 or higher.",
        },
        PciDssRequirement {
            requirement: "Req 6.5",
            title: "Address Common Coding Vulnerabilities in Software-Development Processes",
            description: "Address common coding vulnerabilities in software-development processes including injection flaws, buffer overflows, insecure cryptographic storage, and improper error handling.",
        },
    ]
}
