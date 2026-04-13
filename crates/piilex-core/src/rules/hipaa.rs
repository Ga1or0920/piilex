/// HIPAA Security Rule section descriptions for report generation.
pub struct HipaaSection {
    pub section: &'static str,
    pub title: &'static str,
    pub description: &'static str,
}

pub fn sections() -> Vec<HipaaSection> {
    vec![
        HipaaSection {
            section: "164.502(a)",
            title: "Uses and Disclosures of PHI",
            description: "A covered entity or business associate may not use or disclose protected health information except as permitted or required.",
        },
        HipaaSection {
            section: "164.312(a)(1)",
            title: "Access Control",
            description: "Implement technical policies and procedures for electronic information systems that maintain electronic protected health information to allow access only to those persons or software programs that have been granted access rights.",
        },
        HipaaSection {
            section: "164.312(a)(2)(iv)",
            title: "Encryption and Decryption",
            description: "Implement a mechanism to encrypt and decrypt electronic protected health information.",
        },
        HipaaSection {
            section: "164.312(b)",
            title: "Audit Controls",
            description: "Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use electronic protected health information.",
        },
        HipaaSection {
            section: "164.312(e)(1)",
            title: "Transmission Security",
            description: "Implement technical security measures to guard against unauthorized access to electronic protected health information that is being transmitted over an electronic communications network.",
        },
        HipaaSection {
            section: "164.514(a)",
            title: "De-identification Standard",
            description: "Health information that does not identify an individual and with respect to which there is no reasonable basis to believe that the information can be used to identify an individual is not individually identifiable health information.",
        },
        HipaaSection {
            section: "164.530(c)",
            title: "Administrative Safeguards - Training",
            description: "A covered entity must train all members of its workforce on the policies and procedures with respect to protected health information.",
        },
    ]
}
