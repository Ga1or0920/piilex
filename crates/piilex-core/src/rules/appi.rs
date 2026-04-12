/// APPI (Act on Protection of Personal Information / Japan) article
/// descriptions for report generation.
pub struct AppiArticle {
    pub article: &'static str,
    pub title: &'static str,
    pub description: &'static str,
}

pub fn articles() -> Vec<AppiArticle> {
    vec![
        AppiArticle {
            article: "Art.2(1)",
            title: "Definition of Personal Information",
            description: "Personal information means information relating to a living individual which can identify the specific individual by name, date of birth, or other description contained in such information, or which includes an individual identification code.",
        },
        AppiArticle {
            article: "Art.2(3)",
            title: "Special Care-Required Personal Information",
            description: "Information concerning a person's race, creed, social status, medical history, criminal record, fact of having suffered damage by a crime, and other descriptions requiring special care in handling.",
        },
        AppiArticle {
            article: "Art.17",
            title: "Specifying the Utilization Purpose",
            description: "A personal information handling business operator shall specify the utilization purpose of personal information as much as possible.",
        },
        AppiArticle {
            article: "Art.18",
            title: "Restriction on Utilization Purpose",
            description: "A personal information handling business operator shall not handle personal information beyond the scope necessary for achieving the utilization purpose without obtaining the consent of the person.",
        },
        AppiArticle {
            article: "Art.20",
            title: "Security Control Actions",
            description: "A personal information handling business operator shall take necessary and appropriate action for the security control of personal data including preventing the leakage, loss, or damage of the personal data.",
        },
        AppiArticle {
            article: "Art.23",
            title: "Restriction on Provision to Third Parties",
            description: "A personal information handling business operator shall not provide personal data to a third party without obtaining the prior consent of the person, except in cases prescribed by law.",
        },
        AppiArticle {
            article: "Art.24",
            title: "Restriction on Provision to Third Parties in Foreign Countries",
            description: "A personal information handling business operator shall not provide personal data to a third party in a foreign country without the consent of the person, unless the country has a personal information protection system recognized as equivalent.",
        },
        AppiArticle {
            article: "Art.25",
            title: "Confirmation at the Time of Receiving Provision from Third Parties",
            description: "When receiving personal data from a third party, a personal information handling business operator shall confirm the name and address of the third party and the circumstances of the acquisition.",
        },
        // My Number Act (adjacent)
        AppiArticle {
            article: "MyNumber Act Art.9",
            title: "Restriction on Use of Individual Number",
            description: "No person shall use the Individual Number of another person beyond the scope necessary for the affairs prescribed by this Act (social security, tax, and disaster response).",
        },
        AppiArticle {
            article: "MyNumber Act Art.12",
            title: "Security Measures for Individual Number",
            description: "Any person who handles Individual Numbers shall take necessary measures to prevent leakage, loss, or damage of the specific personal information related to Individual Numbers.",
        },
    ]
}
