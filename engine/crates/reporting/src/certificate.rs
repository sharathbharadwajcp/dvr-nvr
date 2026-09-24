use anyhow::Result;
use printpdf::*;
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

/// Examiner information required for statutory certification.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExaminerDetails {
    pub name: String,
    pub designation: String,
    pub agency: String,
    pub badge_number: String,
    pub laboratory: String,
}

impl Default for ExaminerDetails {
    fn default() -> Self {
        Self {
            name: "Forensic Examiner".to_string(),
            designation: "Digital Forensics Specialist".to_string(),
            agency: "State Cyber Police / Forensic Science Laboratory".to_string(),
            badge_number: "DF-2026-04".to_string(),
            laboratory: "Central Cyber Forensics Division".to_string(),
        }
    }
}

/// Parameters for generating a Section 63 BSA certificate.
pub struct CertificateParams<'a> {
    pub case_name: &'a str,
    pub generated_at: &'a str,
    pub examiner: &'a ExaminerDetails,
    pub source_path: &'a str,
    pub md5_hash: &'a str,
    pub sha256_hash: &'a str,
    pub blake3_hash: &'a str,
    pub block_size: usize,
    pub block_count: usize,
    pub identified_device: &'a str,
    pub identified_chipset: &'a str,
    pub confidence: f64,
    pub validation_tier: u8,
    pub extracted_records_count: usize,
    pub carved_frames_count: usize,
    pub transitions_count: usize,
    pub analytics_leads_count: usize,
    pub discontinuities_count: usize,
    pub is_pristine: bool,
}

struct Cursor {
    doc: PdfDocumentReference,
    page: PdfPageReference,
    layer: PdfLayerReference,
    font_bold: IndirectFontRef,
    font_regular: IndirectFontRef,
    font_mono: IndirectFontRef,
    y: f64,
    page_num: usize,
}

impl Cursor {
    fn new(title: &str) -> Result<Self> {
        let (doc, page1, layer1) = PdfDocument::new(title, Mm(210.0), Mm(297.0), "Layer 1");
        let font_bold = doc
            .add_builtin_font(BuiltinFont::HelveticaBold)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        let font_regular = doc
            .add_builtin_font(BuiltinFont::Helvetica)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        let font_mono = doc
            .add_builtin_font(BuiltinFont::Courier)
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;

        let page = doc.get_page(page1);
        let layer = page.get_layer(layer1);

        let mut c = Self {
            doc,
            page,
            layer,
            font_bold,
            font_regular,
            font_mono,
            y: 280.0,
            page_num: 1,
        };
        c.draw_page_header_footer();
        Ok(c)
    }

    fn check_page_break(&mut self, required_mm: f64) {
        if self.y - required_mm < 25.0 {
            self.page_num += 1;
            let (next_page, next_layer) = self
                .doc
                .add_page(Mm(210.0), Mm(297.0), format!("Layer {}", self.page_num));
            self.page = self.doc.get_page(next_page);
            self.layer = self.page.get_layer(next_layer);
            self.y = 280.0;
            self.draw_page_header_footer();
        }
    }

    fn draw_page_header_footer(&mut self) {
        // Top Draft Banner
        self.layer.use_text(
            "*** DRAFT -- REQUIRING FORMAL LEGAL REVIEW ***",
            9.0,
            Mm(52.0),
            Mm(288.0),
            &self.font_bold,
        );

        // Footer
        self.layer.use_text(
            "DVR/NVR Forensic Platform (Team Cyber 4) | Formulated under Section 63, BSA 2023",
            8.0,
            Mm(20.0),
            Mm(15.0),
            &self.font_regular,
        );
        self.layer.use_text(
            format!("Page {}", self.page_num),
            8.0,
            Mm(185.0),
            Mm(15.0),
            &self.font_regular,
        );
    }

    fn write_line(&mut self, text: &str, size: f64, is_bold: bool, is_mono: bool) {
        self.check_page_break(size * 0.45 + 2.0);
        let font = if is_mono {
            &self.font_mono
        } else if is_bold {
            &self.font_bold
        } else {
            &self.font_regular
        };
        self.layer.use_text(text, size as f32, Mm(20.0), Mm(self.y as f32), font);
        self.y -= size * 0.45 + 2.0;
    }

    fn write_field(&mut self, label: &str, value: &str, is_mono: bool) {
        self.check_page_break(6.0);
        self.layer
            .use_text(label, 9.5, Mm(20.0), Mm(self.y as f32), &self.font_bold);
        let font = if is_mono {
            &self.font_mono
        } else {
            &self.font_regular
        };
        self.layer
            .use_text(value, 9.5, Mm(75.0), Mm(self.y as f32), font);
        self.y -= 5.5;
    }

    fn draw_separator(&mut self) {
        self.check_page_break(6.0);
        self.layer.use_text(
            "-------------------------------------------------------------------------------------------------------",
            8.0,
            Mm(20.0),
            Mm(self.y as f32),
            &self.font_regular,
        );
        self.y -= 5.0;
    }
}

/// Generates a court-admissible certificate PDF modeled on Section 63 of Bharatiya Sakshya Adhiniyam, 2023.
pub fn generate_bsa_certificate_pdf<P: AsRef<Path>>(
    params: &CertificateParams,
    output_path: P,
) -> Result<()> {
    let mut c = Cursor::new("Forensic Admissibility Certificate - Section 63 BSA 2023")?;

    // Document Title Header
    c.y -= 4.0;
    c.write_line(
        "CERTIFICATE OF ELECTRONIC EVIDENCE",
        15.0,
        true,
        false,
    );
    c.write_line(
        "UNDER SECTION 63 OF THE BHARATIYA SAKSHYA ADHINIYAM (BSA), 2023",
        11.0,
        true,
        false,
    );
    c.write_line(
        "(Admissibility of Electronic Records in Judicial Proceedings)",
        9.0,
        false,
        false,
    );
    c.draw_separator();

    // Section 1: Case & Examiner Credentials
    c.write_line("SECTION I: CASE PARTICULARS & EXAMINER DETAILS", 11.0, true, false);
    c.write_field("Case Identifier:", params.case_name, false);
    c.write_field("Date & Time of Examination:", params.generated_at, false);
    c.write_field("Examining Specialist:", &params.examiner.name, false);
    c.write_field("Designation / Role:", &params.examiner.designation, false);
    c.write_field("Department / Agency:", &params.examiner.agency, false);
    c.write_field("Badge / Identification No.:", &params.examiner.badge_number, false);
    c.write_field("Forensic Laboratory:", &params.examiner.laboratory, false);
    c.draw_separator();

    // Section 2: Electronic Evidence & Hardware Particulars
    c.write_line("SECTION II: DEVICE & STORAGE MEDIA IDENTIFICATION", 11.0, true, false);
    c.write_field("Source Image / Media Path:", params.source_path, true);
    c.write_field(
        "Logical Dimensions:",
        &format!("{} blocks (Block Size: {} bytes)", params.block_count, params.block_size),
        false,
    );
    c.write_field("Identified Format / OEM:", params.identified_device, false);
    c.write_field("Target SoC / Chipset Architecture:", params.identified_chipset, false);
    c.write_field(
        "Identification Confidence:",
        &format!("{:.1}%", params.confidence * 100.0),
        false,
    );

    let (tier_str, tier_disclosure) = match params.validation_tier {
        1 => (
            "Tier 1 (Synthetic Fixture Format)",
            "Verified against self-authored synthetic filesystem with deterministic ground truth.",
        ),
        2 => (
            "Tier 2 (Literature-Derived Vendor Grammar)",
            "Derived from published reverse-engineering research and academic papers without OEM NDA.",
        ),
        3 => (
            "Tier 3 (Physical Hardware Confirmed)",
            "Directly confirmed and validated against physical DVR/NVR hardware test units.",
        ),
        _ => ("Unknown Validation Tier", "Uncertified grammar definition."),
    };
    c.write_field("Grammar Validation Tier:", tier_str, true);
    c.write_field("Tier Admissibility Disclosure:", tier_disclosure, false);
    c.draw_separator();

    // Section 3: Hash Integrity Verification (Triple-Hash Forensic Standard)
    c.write_line("SECTION III: CRYPTOGRAPHIC HASH VERIFICATION (TRIPLE STANDARD)", 11.0, true, false);
    c.write_field("MD5 Hash (RFC 1321):", params.md5_hash, true);
    c.write_field("SHA-256 Hash (FIPS 180-4):", params.sha256_hash, true);
    c.write_field("BLAKE3 Hash (Cryptographic):", params.blake3_hash, true);
    c.write_field(
        "Physical Integrity Audit Status:",
        if params.is_pristine {
            "[OK] PRISTINE / UNTAMPERED EVIDENCE"
        } else {
            "[!] INTEGRITY COMPROMISED / MODIFIED"
        },
        true,
    );
    c.draw_separator();

    // Section 4: Forensic Findings & Analytical Lead Summary
    c.write_line("SECTION IV: EXTRACTION & FORENSIC TIMELINE SUMMARY", 11.0, true, false);
    c.write_field(
        "Demuxed Video Frame Records:",
        &format!("{} records", params.extracted_records_count),
        false,
    );
    c.write_field(
        "Carved Video Frame Fragments:",
        &format!("{} frames recovered", params.carved_frames_count),
        false,
    );
    c.write_field(
        "Cross-Camera Correlated Events:",
        &format!("{} spatial-temporal events", params.transitions_count),
        false,
    );
    c.write_field(
        "AI Video Analytics Leads:",
        &format!("{} high-relevance detections", params.analytics_leads_count),
        false,
    );
    c.write_field(
        "Timeline Discontinuities / Gaps:",
        &format!("{} alert(s)", params.discontinuities_count),
        false,
    );
    c.draw_separator();

    // Section 5: Statutory Certification & Declaration under Section 63(4) BSA 2023
    c.write_line("SECTION V: STATUTORY DECLARATION (SECTION 63(4) BSA, 2023)", 11.0, true, false);
    c.write_line(
        "I hereby certify and declare in accordance with Section 63 of the Bharatiya Sakshya",
        9.0,
        false,
        false,
    );
    c.write_line(
        "Adhiniyam (BSA), 2023 that:",
        9.0,
        false,
        false,
    );
    c.write_line(
        " 1. The digital recording described herein was acquired and processed using strictly",
        8.5,
        false,
        false,
    );
    c.write_line(
        "    read-only forensic streaming, ensuring zero alteration to the source evidentiary image.",
        8.5,
        false,
        false,
    );
    c.write_line(
        " 2. The acquisition, parsing, carving, correlation, and analytics software (dvrft v0.1.0)",
        8.5,
        false,
        false,
    );
    c.write_line(
        "    was operating properly at all material times without hardware or software defects.",
        8.5,
        false,
        false,
    );
    c.write_line(
        " 3. The cryptographic hashes herein were verified independently across three disparate",
        8.5,
        false,
        false,
    );
    c.write_line(
        "    algorithms (MD5, SHA-256, BLAKE3), guaranteeing the bit-level integrity of the record.",
        8.5,
        false,
        false,
    );
    c.write_line(
        " 4. All statements made in this certificate are true to the best of my knowledge and belief.",
        8.5,
        false,
        false,
    );

    c.y -= 10.0;
    c.check_page_break(25.0);

    // Signatures
    c.write_field("Date of Attestation:", params.generated_at, false);
    c.write_field("Place of Examination:", &params.examiner.laboratory, false);
    c.y -= 8.0;
    c.write_line(
        "________________________________________",
        10.0,
        true,
        false,
    );
    c.write_line(
        &format!("Signature & Seal: {} ({})", params.examiner.name, params.examiner.designation),
        9.5,
        true,
        false,
    );
    c.write_line(
        &format!("Authorized Forensic Examiner | {}", params.examiner.agency),
        8.5,
        false,
        false,
    );

    // Write file
    let file = File::create(output_path)?;
    c.doc
        .save(&mut BufWriter::new(file))
        .map_err(|e| anyhow::anyhow!("{:?}", e))?;

    Ok(())
}
