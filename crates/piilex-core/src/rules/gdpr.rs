/// GDPR article descriptions for report generation.
pub struct GdprArticle {
    pub article: &'static str,
    pub title: &'static str,
    pub description: &'static str,
}

pub fn articles() -> Vec<GdprArticle> {
    vec![
        GdprArticle {
            article: "Art.5(1f)",
            title: "Integrity and Confidentiality",
            description: "Personal data shall be processed in a manner that ensures appropriate security, including protection against unauthorised or unlawful processing and against accidental loss, destruction or damage.",
        },
        GdprArticle {
            article: "Art.13",
            title: "Information to be Provided Where Personal Data are Collected",
            description: "The controller shall provide the data subject with information about the purposes of processing, recipients of personal data, and the existence of data subject rights.",
        },
        GdprArticle {
            article: "Art.25",
            title: "Data Protection by Design and by Default",
            description: "The controller shall implement appropriate technical and organisational measures for ensuring that only personal data necessary for each specific purpose are processed.",
        },
        GdprArticle {
            article: "Art.30",
            title: "Records of Processing Activities",
            description: "Each controller shall maintain a record of processing activities under its responsibility, including purposes, categories of data subjects, and categories of personal data.",
        },
        GdprArticle {
            article: "Art.32",
            title: "Security of Processing",
            description: "The controller and processor shall implement appropriate technical and organisational measures to ensure a level of security appropriate to the risk.",
        },
        GdprArticle {
            article: "Art.44",
            title: "General Principle for Transfers",
            description: "Any transfer of personal data to a third country shall take place only if the conditions laid down in this Chapter are complied with.",
        },
    ]
}
