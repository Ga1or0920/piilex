use crate::finding::{Finding, FlowNodeKind, Framework, FrameworkMapping, PiiType};

pub struct FrameworkMapper {
    gdpr_rules: Vec<FrameworkRule>,
    ccpa_rules: Vec<FrameworkRule>,
    appi_rules: Vec<FrameworkRule>,
}

struct FrameworkRule {
    article: &'static str,
    title: &'static str,
    trigger: RuleTrigger,
    risk: &'static str,
    recommendation: &'static str,
}

enum RuleTrigger {
    SinkType(FlowNodeKind),
    AnyDataFlow,
    AnySensitiveData,
    /// Triggers on Japan-specific PII types (MyNumber, etc.)
    JapanSpecificPii,
    /// Triggers on biometric data
    BiometricPii,
}

impl Default for FrameworkMapper {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameworkMapper {
    pub fn new() -> Self {
        Self {
            // ── GDPR ────────────────────────────────────────────
            gdpr_rules: vec![
                FrameworkRule {
                    article: "Art.5(1f)",
                    title: "Integrity and Confidentiality",
                    trigger: RuleTrigger::SinkType(FlowNodeKind::LogOutput),
                    risk: "PII written to logs without protection violates data security obligation",
                    recommendation: "Implement log sanitization or masking for PII fields before logging",
                },
                FrameworkRule {
                    article: "Art.13",
                    title: "Information to be Provided",
                    trigger: RuleTrigger::SinkType(FlowNodeKind::ThirdPartyApi),
                    risk: "PII shared with third party without documented legal basis",
                    recommendation: "Document the legal basis for sharing and update privacy notice",
                },
                FrameworkRule {
                    article: "Art.25",
                    title: "Data Protection by Design",
                    trigger: RuleTrigger::AnySensitiveData,
                    risk: "Sensitive PII processed without privacy-by-design safeguards",
                    recommendation: "Apply field-level encryption or pseudonymization for sensitive PII",
                },
                FrameworkRule {
                    article: "Art.30",
                    title: "Records of Processing Activities",
                    trigger: RuleTrigger::SinkType(FlowNodeKind::Database),
                    risk: "PII processing activity detected -- ensure RoPA entry exists",
                    recommendation: "Add this processing activity to your Records of Processing Activities",
                },
                FrameworkRule {
                    article: "Art.32",
                    title: "Security of Processing",
                    trigger: RuleTrigger::SinkType(FlowNodeKind::LogOutput),
                    risk: "PII in logs may be accessible to unauthorized personnel",
                    recommendation: "Restrict log access and implement PII masking in log output",
                },
                FrameworkRule {
                    article: "Art.44",
                    title: "General Principle for Transfers",
                    trigger: RuleTrigger::SinkType(FlowNodeKind::ThirdPartyApi),
                    risk: "PII may be transferred to third-party service outside EU/EEA",
                    recommendation: "Verify data residency of third-party services and implement transfer safeguards",
                },
            ],

            // ── CCPA ────────────────────────────────────────────
            ccpa_rules: vec![
                FrameworkRule {
                    article: "§1798.100(b)",
                    title: "Right to Know -- Collection Disclosure",
                    trigger: RuleTrigger::AnyDataFlow,
                    risk: "Personal information collected without adequate disclosure",
                    recommendation: "Update privacy policy to disclose categories of PI collected and purposes",
                },
                FrameworkRule {
                    article: "§1798.100(d)",
                    title: "Data Minimization",
                    trigger: RuleTrigger::AnySensitiveData,
                    risk: "Sensitive personal information may exceed what is necessary",
                    recommendation: "Review data collection to ensure minimization principle is met",
                },
                FrameworkRule {
                    article: "§1798.150",
                    title: "Personal Information Security",
                    trigger: RuleTrigger::SinkType(FlowNodeKind::LogOutput),
                    risk: "Unprotected personal information in logs creates breach liability",
                    recommendation: "Encrypt or mask personal information before logging to prevent breach exposure",
                },
            ],

            // ── APPI (Japan) ────────────────────────────────────
            appi_rules: vec![
                // Art.17: Specifying the purpose of use
                FrameworkRule {
                    article: "Art.17",
                    title: "Specifying Utilization Purpose",
                    trigger: RuleTrigger::AnyDataFlow,
                    risk: "Personal information collected without specified utilization purpose",
                    recommendation: "Specify and document the utilization purpose for this personal information as required by APPI Art.17",
                },
                // Art.20: Security control actions
                FrameworkRule {
                    article: "Art.20",
                    title: "Security Control Actions",
                    trigger: RuleTrigger::SinkType(FlowNodeKind::LogOutput),
                    risk: "Personal information leaked to logs without security controls",
                    recommendation: "Implement necessary and appropriate security control actions (access control, encryption, masking) per APPI Art.20",
                },
                // Art.20: Security for database storage
                FrameworkRule {
                    article: "Art.20",
                    title: "Security Control Actions (Storage)",
                    trigger: RuleTrigger::SinkType(FlowNodeKind::Database),
                    risk: "Personal information stored without adequate security controls",
                    recommendation: "Apply encryption at rest and access control for personal information databases per APPI Art.20",
                },
                // Art.23: Restriction on third-party provision
                FrameworkRule {
                    article: "Art.23",
                    title: "Restriction on Provision to Third Parties",
                    trigger: RuleTrigger::SinkType(FlowNodeKind::ThirdPartyApi),
                    risk: "Personal information provided to third party without consent",
                    recommendation: "Obtain prior consent from the data subject before providing personal information to third parties per APPI Art.23",
                },
                // Art.24: Restriction on cross-border transfer
                FrameworkRule {
                    article: "Art.24",
                    title: "Restriction on Cross-Border Transfer",
                    trigger: RuleTrigger::SinkType(FlowNodeKind::ThirdPartyApi),
                    risk: "Personal information may be transferred to a foreign third party",
                    recommendation: "Ensure foreign transfer complies with APPI Art.24 (consent, adequate protection, or contractual safeguards)",
                },
                // Art.2(3): Sensitive personal information (special care-required)
                FrameworkRule {
                    article: "Art.2(3)",
                    title: "Special Care-Required Personal Information",
                    trigger: RuleTrigger::AnySensitiveData,
                    risk: "Special care-required personal information detected (race, creed, social status, medical history, criminal record, etc.)",
                    recommendation: "Obtain explicit consent before acquiring special care-required personal information per APPI Art.2(3) and Art.20(2)",
                },
                // Biometric data under APPI
                FrameworkRule {
                    article: "Art.2(3)",
                    title: "Special Care-Required Personal Information (Biometric)",
                    trigger: RuleTrigger::BiometricPii,
                    risk: "Biometric data classified as special care-required personal information under APPI",
                    recommendation: "Apply strict access controls and obtain explicit consent for biometric data processing",
                },
                // My Number Act (adjacent to APPI)
                FrameworkRule {
                    article: "MyNumber Act Art.9",
                    title: "Restriction on Use of Individual Number",
                    trigger: RuleTrigger::JapanSpecificPii,
                    risk: "Individual Number (My Number) detected -- use is strictly restricted to social security, tax, and disaster response",
                    recommendation: "Ensure My Number is used only for legally permitted purposes. Apply encryption and strict access control per My Number Act Art.9 and Art.12",
                },
                // My Number Act: Security
                FrameworkRule {
                    article: "MyNumber Act Art.12",
                    title: "Security Measures for Individual Number",
                    trigger: RuleTrigger::JapanSpecificPii,
                    risk: "Individual Number may be exposed without required security measures",
                    recommendation: "Implement necessary measures to prevent leakage, loss, or damage of Individual Numbers per My Number Act Art.12",
                },
            ],
        }
    }

    pub fn map_findings(&self, findings: &mut [Finding], framework: Framework) {
        for finding in findings.iter_mut() {
            match framework {
                Framework::Gdpr => self.apply_rules(finding, &self.gdpr_rules, Framework::Gdpr),
                Framework::Ccpa => self.apply_rules(finding, &self.ccpa_rules, Framework::Ccpa),
                Framework::Appi => self.apply_rules(finding, &self.appi_rules, Framework::Appi),
            }
        }
    }

    fn apply_rules(&self, finding: &mut Finding, rules: &[FrameworkRule], framework: Framework) {
        for rule in rules {
            if self.rule_matches(&rule.trigger, finding) {
                finding.framework_mappings.push(FrameworkMapping {
                    framework,
                    article: rule.article.to_string(),
                    title: rule.title.to_string(),
                    risk_description: rule.risk.to_string(),
                    recommendation: rule.recommendation.to_string(),
                });
            }
        }
    }

    fn rule_matches(&self, trigger: &RuleTrigger, finding: &Finding) -> bool {
        match trigger {
            RuleTrigger::SinkType(expected_kind) => finding
                .data_flow
                .as_ref()
                .map(|df| df.sink.kind == *expected_kind)
                .unwrap_or(false),
            RuleTrigger::AnyDataFlow => finding.data_flow.is_some(),
            RuleTrigger::AnySensitiveData => matches!(
                finding.pii_type,
                PiiType::NationalId
                    | PiiType::CreditCard
                    | PiiType::Password
                    | PiiType::HealthData
                    | PiiType::MedicalRecord
                    | PiiType::PassportNumber
                    | PiiType::BankAccount
                    | PiiType::MyNumber
                    | PiiType::Biometric
                    | PiiType::Fingerprint
                    | PiiType::FaceImage
                    | PiiType::Diagnosis
                    | PiiType::Prescription
            ),
            RuleTrigger::JapanSpecificPii => {
                matches!(finding.pii_type, PiiType::MyNumber | PiiType::NationalId)
            }
            RuleTrigger::BiometricPii => matches!(
                finding.pii_type,
                PiiType::Biometric | PiiType::Fingerprint | PiiType::FaceImage
            ),
        }
    }
}
