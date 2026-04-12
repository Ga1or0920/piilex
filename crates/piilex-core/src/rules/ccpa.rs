/// CCPA section descriptions for report generation.
pub struct CcpaSection {
    pub section: &'static str,
    pub title: &'static str,
    pub description: &'static str,
}

pub fn sections() -> Vec<CcpaSection> {
    vec![
        CcpaSection {
            section: "§1798.100(b)",
            title: "Right to Know — Collection Disclosure",
            description: "A business that collects a consumer's personal information shall disclose the categories of personal information collected and the purposes for which the information is used.",
        },
        CcpaSection {
            section: "§1798.100(d)",
            title: "Data Minimization",
            description: "A business shall not collect additional categories of personal information or use personal information for additional purposes without providing the consumer with notice.",
        },
        CcpaSection {
            section: "§1798.150",
            title: "Personal Information Security",
            description: "Any consumer whose nonencrypted and nonredacted personal information is subject to unauthorized access may institute a civil action for damages.",
        },
    ]
}
