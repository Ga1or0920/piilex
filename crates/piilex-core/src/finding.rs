use crate::severity::Severity;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub pii_type: PiiType,
    pub category: PiiCategory,
    pub location: SourceLocation,
    pub code_snippet: String,
    pub data_flow: Option<DataFlow>,
    pub framework_mappings: Vec<FrameworkMapping>,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PiiType {
    // -- Contact (5)
    Email,
    PhoneNumber,
    Address,
    PostalCode,
    Fax,
    // -- Personal attributes (7)
    FullName,
    FirstName,
    LastName,
    DateOfBirth,
    Gender,
    Nationality,
    Ethnicity,
    // -- Government identifiers (9)
    NationalId,
    PassportNumber,
    DriversLicense,
    TaxId,
    VoterId,
    MyNumber, // Japan
    Iban,     // EU/intl
    Bsn,      // Netherlands
    Nhs,      // UK
    // -- Financial (7)
    CreditCard,
    BankAccount,
    Salary,
    BankRoutingNumber,
    SwiftCode,
    CryptoWallet,
    InsuranceId,
    // -- Auth credentials (5)
    Password,
    AuthToken,
    ApiKey,
    PrivateKey,
    SecretKey,
    // -- Health (4)
    HealthData,
    MedicalRecord,
    Diagnosis,
    Prescription,
    // -- Biometric / physical (3)
    Biometric,
    FaceImage,
    Fingerprint,
    // -- Digital identifiers (7)
    IpAddress,
    MacAddress,
    UserAgent,
    DeviceId,
    Cookie,
    SessionId,
    GpsCoordinates,
    // -- Education / employment (3)
    StudentId,
    EmployeeId,
    SocialMediaHandle,
    // -- Custom (user-defined via .piilex.yml)
    Custom(String),
}

impl PiiType {
    pub fn as_str(&self) -> &str {
        match self {
            PiiType::Email => "email",
            PiiType::PhoneNumber => "phone_number",
            PiiType::Address => "address",
            PiiType::PostalCode => "postal_code",
            PiiType::Fax => "fax",
            PiiType::FullName => "full_name",
            PiiType::FirstName => "first_name",
            PiiType::LastName => "last_name",
            PiiType::DateOfBirth => "date_of_birth",
            PiiType::Gender => "gender",
            PiiType::Nationality => "nationality",
            PiiType::Ethnicity => "ethnicity",
            PiiType::NationalId => "national_id",
            PiiType::PassportNumber => "passport_number",
            PiiType::DriversLicense => "drivers_license",
            PiiType::TaxId => "tax_id",
            PiiType::VoterId => "voter_id",
            PiiType::MyNumber => "my_number",
            PiiType::Iban => "iban",
            PiiType::Bsn => "bsn",
            PiiType::Nhs => "nhs",
            PiiType::CreditCard => "credit_card",
            PiiType::BankAccount => "bank_account",
            PiiType::Salary => "salary",
            PiiType::BankRoutingNumber => "bank_routing_number",
            PiiType::SwiftCode => "swift_code",
            PiiType::CryptoWallet => "crypto_wallet",
            PiiType::InsuranceId => "insurance_id",
            PiiType::Password => "password",
            PiiType::AuthToken => "auth_token",
            PiiType::ApiKey => "api_key",
            PiiType::PrivateKey => "private_key",
            PiiType::SecretKey => "secret_key",
            PiiType::HealthData => "health_data",
            PiiType::MedicalRecord => "medical_record",
            PiiType::Diagnosis => "diagnosis",
            PiiType::Prescription => "prescription",
            PiiType::Biometric => "biometric",
            PiiType::FaceImage => "face_image",
            PiiType::Fingerprint => "fingerprint",
            PiiType::IpAddress => "ip_address",
            PiiType::MacAddress => "mac_address",
            PiiType::UserAgent => "user_agent",
            PiiType::DeviceId => "device_id",
            PiiType::Cookie => "cookie",
            PiiType::SessionId => "session_id",
            PiiType::GpsCoordinates => "gps_coordinates",
            PiiType::StudentId => "student_id",
            PiiType::EmployeeId => "employee_id",
            PiiType::SocialMediaHandle => "social_media_handle",
            PiiType::Custom(name) => name.as_str(),
        }
    }
}

impl std::fmt::Display for PiiType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PiiCategory {
    ContactInfo,
    PersonalAttribute,
    GovernmentId,
    FinancialInfo,
    AuthCredential,
    HealthInfo,
    BiometricData,
    BrowserDevice,
    NetworkIdentifier,
    EducationEmployment,
    Custom,
}

impl PiiCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            PiiCategory::ContactInfo => "contact_info",
            PiiCategory::PersonalAttribute => "personal_attribute",
            PiiCategory::GovernmentId => "government_id",
            PiiCategory::FinancialInfo => "financial_info",
            PiiCategory::AuthCredential => "auth_credential",
            PiiCategory::HealthInfo => "health_info",
            PiiCategory::BiometricData => "biometric_data",
            PiiCategory::BrowserDevice => "browser_device",
            PiiCategory::NetworkIdentifier => "network_identifier",
            PiiCategory::EducationEmployment => "education_employment",
            PiiCategory::Custom => "custom",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceLocation {
    pub file: PathBuf,
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlow {
    pub source: DataFlowNode,
    pub sink: DataFlowNode,
    pub path: Vec<SourceLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowNode {
    pub kind: FlowNodeKind,
    pub label: String,
    pub location: SourceLocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowNodeKind {
    UserInput,
    Database,
    LogOutput,
    ThirdPartyApi,
    FileSystem,
    Response,
    Environment,
}

impl FlowNodeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            FlowNodeKind::UserInput => "user_input",
            FlowNodeKind::Database => "database",
            FlowNodeKind::LogOutput => "log_output",
            FlowNodeKind::ThirdPartyApi => "third_party_api",
            FlowNodeKind::FileSystem => "file_system",
            FlowNodeKind::Response => "response",
            FlowNodeKind::Environment => "environment",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Framework {
    Gdpr,
    Ccpa,
    Appi,
}

impl Framework {
    pub fn as_str(&self) -> &'static str {
        match self {
            Framework::Gdpr => "gdpr",
            Framework::Ccpa => "ccpa",
            Framework::Appi => "appi",
        }
    }
}

impl std::str::FromStr for Framework {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "gdpr" => Ok(Framework::Gdpr),
            "ccpa" => Ok(Framework::Ccpa),
            "appi" => Ok(Framework::Appi),
            _ => Err(format!(
                "unknown framework: '{s}' (expected: gdpr, ccpa, appi)"
            )),
        }
    }
}

impl std::fmt::Display for Framework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkMapping {
    pub framework: Framework,
    pub article: String,
    pub title: String,
    pub risk_description: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingSet {
    pub findings: Vec<Finding>,
    pub metadata: ScanMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetadata {
    pub path: PathBuf,
    pub files_scanned: usize,
    pub files_skipped: usize,
    #[serde(with = "duration_millis")]
    pub duration: Duration,
    pub frameworks: Vec<Framework>,
    pub tool_version: String,
}

mod duration_millis {
    use serde::{self, Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(duration.as_millis() as u64)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(millis))
    }
}
