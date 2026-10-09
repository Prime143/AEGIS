/**
 * AEGIS: AI-Enabled Governance & Information Security
 * NOVA Systems Synthetic Research Dataset Generator
 * 
 * Locked Research Question:
 * "How much does organization-specific adaptation improve sensitive-information detection
 *  in employee–AI prompts, and what does it cost to keep that detection local?"
 * 
 * Deterministic generation script using seed 42.
 * Annotation Status: PENDING HUMAN VALIDATION
 */

import * as fs from 'fs';
import * as path from 'path';

export type GoldClass =
  | 'PII'
  | 'secrets'
  | 'internal identifiers'
  | 'confidential technical/financial information'
  | 'benign';

export type SensitivityLevel = 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';

export interface NovaDatasetRecord {
  id: string;
  text: string;
  gold_class: GoldClass;
  sensitivity_level: SensitivityLevel;
  entity_category: string;
  terminology_group: string;
  seen_or_unseen: 'SEEN' | 'UNSEEN';
  template_family: string;
  split: 'TRAIN' | 'DEV' | 'TEST';
  hard_negative_group: string | null;
  annotation_status: 'PENDING HUMAN VALIDATION';
}

// Simple deterministic Mulberry32 PRNG
function mulberry32(a: number) {
  return function () {
    let t = (a += 0x6d2b79f5);
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const rng = mulberry32(42);

function choice<T>(arr: T[]): T {
  return arr[Math.floor(rng() * arr.length)];
}

const records: NovaDatasetRecord[] = [];
let idCounter = 1;

function nextId(): string {
  const s = String(idCounter++).padStart(4, '0');
  return `nova-${s}`;
}

function addRecord(rec: Omit<NovaDatasetRecord, 'id' | 'annotation_status'>): void {
  records.push({
    id: nextId(),
    annotation_status: 'PENDING HUMAN VALIDATION',
    ...rec,
  });
}

// =========================================================================
// 1. CONTEXTUAL HARD NEGATIVE PAIRS (SEEN & UNSEEN)
// Every pair contains:
// - A BENIGN prompt (public domain / scientific / mythological / linguistic)
// - A SENSITIVE prompt (internal proprietary NOVA Systems engineering / finance)
// =========================================================================

// --- SEEN HARD NEGATIVE PAIRS (TRAIN and DEV splits) ---
const seenHardNegativePairs: Array<{
  group: string;
  term: string;
  benignText: string;
  sensitiveText: string;
  sensitiveClass: GoldClass;
  sensitiveLevel: SensitivityLevel;
  category: string;
  split: 'TRAIN' | 'DEV';
}> = [
  // Aurora (Seen) - Project Aurora (hypersonic telemetry) vs Aurora Borealis / Amazon Aurora / City
  {
    group: 'HN-AURORA-01',
    term: 'aurora',
    benignText: 'The aurora borealis produced vivid geomagnetic displays across northern Norway and Iceland last night.',
    sensitiveText: 'Ensure the Project Aurora hypersonic telemetry logs are archived prior to the wind-tunnel test.',
    sensitiveClass: 'confidential technical/financial information',
    sensitiveLevel: 'CONFIDENTIAL',
    category: 'CONFIDENTIAL_TECHNICAL',
    split: 'TRAIN',
  },
  {
    group: 'HN-AURORA-02',
    term: 'aurora',
    benignText: 'We are migrating our public analytics pipeline to Amazon Aurora PostgreSQL serverless instances.',
    sensitiveText: 'Update the Aurora-V flight computer firmware flashing instructions on the internal engineering wiki.',
    sensitiveClass: 'confidential technical/financial information',
    sensitiveLevel: 'CONFIDENTIAL',
    category: 'CONFIDENTIAL_TECHNICAL',
    split: 'TRAIN',
  },
  {
    group: 'HN-AURORA-03',
    term: 'aurora',
    benignText: 'The city council of Aurora, Illinois approved funding for municipal park infrastructure upgrades.',
    sensitiveText: 'The Project Aurora inertial guidance calibration offsets must not be checked into public repositories.',
    sensitiveClass: 'confidential technical/financial information',
    sensitiveLevel: 'CONFIDENTIAL',
    category: 'CONFIDENTIAL_TECHNICAL',
    split: 'DEV',
  },
  {
    group: 'HN-AURORA-04',
    term: 'aurora',
    benignText: 'In classical Roman mythology, Aurora is revered as the radiant goddess of the dawn.',
    sensitiveText: 'Please review ticket NOVA-ENG-1042 regarding the Project Aurora stage 2 telemetry bus fault.',
    sensitiveClass: 'internal identifiers',
    sensitiveLevel: 'INTERNAL',
    category: 'INTERNAL_IDENTIFIER',
    split: 'DEV',
  },

  // Valkyrie (Seen) - Valkyrie-X (autonomous swarm guidance) vs Norse mythology / XB-70 Valkyrie
  {
    group: 'HN-VALKYRIE-01',
    term: 'valkyrie',
    benignText: 'In Norse mythology, the Valkyries were female figures who chose who was slain in battle and escorted heroes to Valhalla.',
    sensitiveText: 'The Valkyrie-X swarm routing algorithm utilizes decentralized mesh consensus to coordinate drone intercept vectors.',
    sensitiveClass: 'confidential technical/financial information',
    sensitiveLevel: 'RESTRICTED',
    category: 'CONFIDENTIAL_TECHNICAL',
    split: 'TRAIN',
  },
  {
    group: 'HN-VALKYRIE-02',
    term: 'valkyrie',
    benignText: 'The North American XB-70 Valkyrie was a supersonic prototype strategic bomber developed during the late 1950s.',
    sensitiveText: 'Refactor the Valkyrie-X guidance loop to clamp collision avoidance thrust impulses to under 45 milliseconds.',
    sensitiveClass: 'confidential technical/financial information',
    sensitiveLevel: 'RESTRICTED',
    category: 'CONFIDENTIAL_TECHNICAL',
    split: 'TRAIN',
  },
  {
    group: 'HN-VALKYRIE-03',
    term: 'valkyrie',
    benignText: 'Richard Wagner composed the famous Ride of the Valkyries as the beginning of Act III in Die Walküre.',
    sensitiveText: 'Upload the Valkyrie-X target classification neural weight checkpoint to vault-01.mgmt.novasystems.net.',
    sensitiveClass: 'confidential technical/financial information',
    sensitiveLevel: 'RESTRICTED',
    category: 'CONFIDENTIAL_TECHNICAL',
    split: 'DEV',
  },

  // Zephyr (Seen) - Zephyr-OS (UAV microkernel) vs gentle breeze / Linux Foundation Zephyr RTOS
  {
    group: 'HN-ZEPHYR-01',
    term: 'zephyr',
    benignText: 'The morning hike was accompanied by a gentle summer zephyr blowing off the coastal cliffs.',
    sensitiveText: 'Compile the Zephyr-OS proprietary kernel module with RT-Preempt scheduling patches enabled for NV-HW-REV3-B.',
    sensitiveClass: 'confidential technical/financial information',
    sensitiveLevel: 'CONFIDENTIAL',
    category: 'CONFIDENTIAL_TECHNICAL',
    split: 'TRAIN',
  },
  {
    group: 'HN-ZEPHYR-02',
    term: 'zephyr',
    benignText: 'The Zephyr Project is a scalable real-time operating system hosted by the Linux Foundation under the Apache 2.0 license.',
    sensitiveText: 'The Zephyr-OS secure boot key signing ceremony is scheduled for Thursday with the Chief Information Security Officer.',
    sensitiveClass: 'confidential technical/financial information',
    sensitiveLevel: 'CONFIDENTIAL',
    category: 'CONFIDENTIAL_TECHNICAL',
    split: 'TRAIN',
  },
  {
    group: 'HN-ZEPHYR-03',
    term: 'zephyr',
    benignText: 'Historical steam locomotives of the Burlington Zephyr class set long-distance passenger speed records across the Midwest.',
    sensitiveText: 'Run memory leak profiling on repository novasys-avionics/telemetry-daemon running under Zephyr-OS build 4.12.',
    sensitiveClass: 'internal identifiers',
    sensitiveLevel: 'INTERNAL',
    category: 'INTERNAL_IDENTIFIER',
    split: 'DEV',
  },

  // Apex (Seen) - Project Apex (M&A takeover of SkyLink Dynamics) vs apex predator / geometry / Apex Legends
  {
    group: 'HN-APEX-01',
    term: 'apex',
    benignText: 'The great white shark occupies the position of apex predator in diverse marine ecosystems worldwide.',
    sensitiveText: 'The Project Apex financial due diligence model values SkyLink Dynamics at $140M pending antitrust clearance.',
    sensitiveClass: 'confidential technical/financial information',
    sensitiveLevel: 'RESTRICTED',
    category: 'CONFIDENTIAL_FINANCIAL',
    split: 'TRAIN',
  },
  {
    group: 'HN-APEX-02',
    term: 'apex',
    benignText: 'Calculate the coordinates of the apex vertex in a three-dimensional regular right square pyramid given base length b.',
    sensitiveText: 'Draft an executive briefing summarizing Project Apex acquisition terms and EBITDA post-merger synergies.',
    sensitiveClass: 'confidential technical/financial information',
    sensitiveLevel: 'RESTRICTED',
    category: 'CONFIDENTIAL_FINANCIAL',
    split: 'TRAIN',
  },
  {
    group: 'HN-APEX-03',
    term: 'apex',
    benignText: 'Apex Legends season updates regularly adjust weapon recoil patterns and legend movement abilities.',
    sensitiveText: 'Do not distribute the Project Apex capitalization table to unauthorized personnel prior to board ratification.',
    sensitiveClass: 'confidential technical/financial information',
    sensitiveLevel: 'RESTRICTED',
    category: 'CONFIDENTIAL_FINANCIAL',
    split: 'DEV',
  },
];

// --- UNSEEN HARD NEGATIVE PAIRS (TEST split only) ---
const unseenHardNegativePairs: Array<{
  group: string;
  term: string;
  benignText: string;
  sensitiveText: string;
  sensitiveClass: GoldClass;
  sensitiveLevel: SensitivityLevel;
  category: string;
}> = [
  // Chimera (Unseen) - Project Chimera (directed energy payload) vs Greek mythology / genetic chimera
  {
    group: 'HN-CHIMERA-01',
    term: 'chimera',
    benignText: 'In classical Greek mythology, the Chimera was a monstrous fire-breathing hybrid creature composed of lion, goat, and serpent.',
    sensitiveText: 'Project Chimera directed-energy pulse repetition interval must remain locked between 120Hz and 140Hz to prevent emitter overheating.',
    sensitiveClass: 'confidential technical/financial information',
    sensitiveLevel: 'RESTRICTED',
    category: 'CONFIDENTIAL_TECHNICAL',
  },
  {
    group: 'HN-CHIMERA-02',
    term: 'chimera',
    benignText: 'A genetic chimera is a single organism composed of cells with more than one distinct genotype resulting from zygotic fusion.',
    sensitiveText: 'Verify whether the beam modulation schema for Project Chimera has been uploaded to grid-quantum.internal.novasystems.net.',
    sensitiveClass: 'confidential technical/financial information',
    sensitiveLevel: 'RESTRICTED',
    category: 'CONFIDENTIAL_TECHNICAL',
  },
  {
    group: 'HN-CHIMERA-03',
    term: 'chimera',
    benignText: 'The paleontologists debated whether the fossil specimen was a genuine transitional species or an anatomical chimera.',
    sensitiveText: 'Assign Jira issue NOVA-PAYLOAD-9011 to senior staff for Project Chimera thermal dissipation simulation.',
    sensitiveClass: 'internal identifiers',
    sensitiveLevel: 'INTERNAL',
    category: 'INTERNAL_IDENTIFIER',
  },

  // Hyperion (Unseen) - Project Hyperion (laser satellite optical downlink) vs Saturn moon / Dan Simmons novel
  {
    group: 'HN-HYPERION-01',
    term: 'hyperion',
    benignText: 'Hyperion is a chaotic tumbling moon of Saturn characterized by an irregular spongy appearance and low density.',
    sensitiveText: 'The Project Hyperion optical laser downlink achieves 40 Gbps aggregate throughput across low Earth orbit relays.',
    sensitiveClass: 'confidential technical/financial information',
    sensitiveLevel: 'CONFIDENTIAL',
    category: 'CONFIDENTIAL_TECHNICAL',
  },
  {
    group: 'HN-HYPERION-02',
    term: 'hyperion',
    benignText: 'The Hyperion Cantos is an acclaimed science fiction series written by Dan Simmons featuring the enigmatic Shrike.',
    sensitiveText: 'Debug the quantum key distribution negotiation phase in repository novasys-optics/laser-downlink for Project Hyperion.',
    sensitiveClass: 'confidential technical/financial information',
    sensitiveLevel: 'CONFIDENTIAL',
    category: 'CONFIDENTIAL_TECHNICAL',
  },
  {
    group: 'HN-HYPERION-03',
    term: 'hyperion',
    benignText: 'The coast redwood known as Hyperion in Northern California holds the record as the worlds tallest living tree at 115 meters.',
    sensitiveText: 'Review the phase jitter calibration tolerances for Project Hyperion ground tracking stations in Australasia.',
    sensitiveClass: 'confidential technical/financial information',
    sensitiveLevel: 'CONFIDENTIAL',
    category: 'CONFIDENTIAL_TECHNICAL',
  },

  // Cerberus (Unseen) - Project Cerberus (zero-trust microsegmentation gateway) vs mythological three-headed hound
  {
    group: 'HN-CERBERUS-01',
    term: 'cerberus',
    benignText: 'In Greek and Roman mythology, Cerberus was the multi-headed hound that guarded the entrance to the underworld.',
    sensitiveText: 'Project Cerberus enforces mutual TLS and ephemeral SPIFFE identities across all tactical edge nodes.',
    sensitiveClass: 'confidential technical/financial information',
    sensitiveLevel: 'CONFIDENTIAL',
    category: 'CONFIDENTIAL_TECHNICAL',
  },
  {
    group: 'HN-CERBERUS-02',
    term: 'cerberus',
    benignText: 'Cerberus was an obsolete northern constellation created by Johannes Hevelius depicting three serpents held by Hercules.',
    sensitiveText: 'Commit the updated firewall rule tables for Project Cerberus to secure-broker.prod.novasystems.net.',
    sensitiveClass: 'internal identifiers',
    sensitiveLevel: 'INTERNAL',
    category: 'INTERNAL_IDENTIFIER',
  },

  // Talon (Unseen) - Project Talon (hostile takeover bid of AeroPrecision) vs bird claw / T-38 aircraft
  {
    group: 'HN-TALON-01',
    term: 'talon',
    benignText: 'The harpy eagle possesses rear talons measuring up to 13 centimeters, enabling it to snatch arboreal mammals from trees.',
    sensitiveText: 'The Project Talon tender offer proposes purchasing AeroPrecision Corp outstanding shares at $42.50 per share in cash.',
    sensitiveClass: 'confidential technical/financial information',
    sensitiveLevel: 'RESTRICTED',
    category: 'CONFIDENTIAL_FINANCIAL',
  },
  {
    group: 'HN-TALON-02',
    term: 'talon',
    benignText: 'The Northrop T-38 Talon is a twin-engine supersonic jet trainer utilized extensively by the United States Air Force and NASA.',
    sensitiveText: 'Prepare the confidential antitrust disclosure filing for Project Talon before the investment banking syndicate meeting.',
    sensitiveClass: 'confidential technical/financial information',
    sensitiveLevel: 'RESTRICTED',
    category: 'CONFIDENTIAL_FINANCIAL',
  },

  // Sentinel-6 (Unseen) - Sentinel-6 classified sensor suite vs NASA/ESA oceanography satellite
  {
    group: 'HN-SENTINEL-01',
    term: 'sentinel-6',
    benignText: 'The Sentinel-6 Michael Freilich satellite was launched in November 2020 to measure global sea level rise using radar altimetry.',
    sensitiveText: 'The Sentinel-6 sensor fusion subsystem integrates synthetic aperture radar with electro-optical tracking at 120 FPS.',
    sensitiveClass: 'confidential technical/financial information',
    sensitiveLevel: 'CONFIDENTIAL',
    category: 'CONFIDENTIAL_TECHNICAL',
  },
  {
    group: 'HN-SENTINEL-02',
    term: 'sentinel-6',
    benignText: 'Public climate data from the Jason-3 and Sentinel-6 satellite series is distributed openly by EUMETSAT and NOAA.',
    sensitiveText: 'Calibration coefficients for sensor NV-SENSOR-S6 on the Sentinel-6 mast must be verified against dark-field baseline noise.',
    sensitiveClass: 'internal identifiers',
    sensitiveLevel: 'INTERNAL',
    category: 'INTERNAL_IDENTIFIER',
  },
];

// Add seen hard negative pairs
for (const p of seenHardNegativePairs) {
  // Benign counterpart
  addRecord({
    text: p.benignText,
    gold_class: 'benign',
    sensitivity_level: 'PUBLIC',
    entity_category: 'BENIGN',
    terminology_group: `${p.term}_negative_seen`,
    seen_or_unseen: 'SEEN',
    template_family: 'contextual_hard_negative',
    split: p.split,
    hard_negative_group: p.group,
  });
  // Sensitive counterpart
  addRecord({
    text: p.sensitiveText,
    gold_class: p.sensitiveClass,
    sensitivity_level: p.sensitiveLevel,
    entity_category: p.category,
    terminology_group: `${p.term}_sensitive_seen`,
    seen_or_unseen: 'SEEN',
    template_family: 'contextual_hard_negative',
    split: p.split,
    hard_negative_group: p.group,
  });
}

// Add unseen hard negative pairs (TEST split strictly)
for (const p of unseenHardNegativePairs) {
  // Benign counterpart
  addRecord({
    text: p.benignText,
    gold_class: 'benign',
    sensitivity_level: 'PUBLIC',
    entity_category: 'BENIGN',
    terminology_group: `${p.term}_negative_unseen`,
    seen_or_unseen: 'UNSEEN',
    template_family: 'contextual_hard_negative',
    split: 'TEST',
    hard_negative_group: p.group,
  });
  // Sensitive counterpart
  addRecord({
    text: p.sensitiveText,
    gold_class: p.sensitiveClass,
    sensitivity_level: p.sensitiveLevel,
    entity_category: p.category,
    terminology_group: `${p.term}_sensitive_unseen`,
    seen_or_unseen: 'UNSEEN',
    template_family: 'contextual_hard_negative',
    split: 'TEST',
    hard_negative_group: p.group,
  });
}

// =========================================================================
// 2. TARGET CLASS 1: PII (EMPLOYEE, CANDIDATE, EXECUTIVE IDENTIFIERS)
// SSNs, phone numbers, home addresses, HR compensation, salary records
// =========================================================================

// --- SEEN PII (TRAIN & DEV) ---
const seenPiiPrompts: Array<{
  text: string;
  level: SensitivityLevel;
  template: string;
  split: 'TRAIN' | 'DEV';
}> = [
  {
    text: 'Please draft an onboarding welcome letter for Sarah Jenkins, SSN 452-98-1124, who joined as principal avionics architect.',
    level: 'RESTRICTED',
    template: 'hr_onboarding',
    split: 'TRAIN',
  },
  {
    text: 'Confirm contact details for Dr. Marcus Vance: personal cellular +1-312-555-8921 and home address 742 Evergreen Terr, Seattle WA.',
    level: 'CONFIDENTIAL',
    template: 'employee_directory',
    split: 'TRAIN',
  },
  {
    text: 'The background check for avionics engineer David Miller lists Social Security Number 098-76-5432. Please confirm clearance.',
    level: 'RESTRICTED',
    template: 'security_clearance',
    split: 'TRAIN',
  },
  {
    text: 'Send severance package breakdown to former employee Elena Rostova at private email elena.rostova.personal@gmail.com.',
    level: 'CONFIDENTIAL',
    template: 'hr_severance',
    split: 'TRAIN',
  },
  {
    text: 'Parse the payroll tax slip for employee badge NV-EMP-44910 with annual base salary of $194,500 and 401k contribution of 6%.',
    level: 'CONFIDENTIAL',
    template: 'payroll_accounting',
    split: 'TRAIN',
  },
  {
    text: 'Update employee emergency contact for Rachel Chang: spouse Robert Chang at mobile phone 415-555-9082.',
    level: 'CONFIDENTIAL',
    template: 'employee_directory',
    split: 'TRAIN',
  },
  {
    text: 'The internal medical leave report indicates engineer Tyler Brooks (SSN 871-33-4019) is out on temporary medical disability.',
    level: 'RESTRICTED',
    template: 'hr_medical',
    split: 'TRAIN',
  },
  {
    text: 'Compile executive bonus allocation table: CEO Robert H. Sterling received $450,000 cash bonus and 12,000 RSUs.',
    level: 'RESTRICTED',
    template: 'executive_compensation',
    split: 'TRAIN',
  },
  {
    text: 'Verify the bank routing information for direct deposit: Account 9876543210, Routing 121000358 for employee Samantha Reed.',
    level: 'RESTRICTED',
    template: 'payroll_accounting',
    split: 'TRAIN',
  },
  {
    text: 'Candidate Arthur Pendelton passed technical screen. Mobile: +1 617-555-0144, Personal Email: arthur.p.aero@outlook.com.',
    level: 'INTERNAL',
    template: 'candidate_recruiting',
    split: 'TRAIN',
  },
  {
    text: 'Draft reprimand memo for engineer Kevin Zhao regarding badge NV-EMP-88213 policy non-compliance during offsite testing.',
    level: 'CONFIDENTIAL',
    template: 'hr_disciplinary',
    split: 'TRAIN',
  },
  {
    text: 'Review corporate credit card statement for VP Operations: Visa ending in 4112-9981-0023-7711 with balance $14,290.',
    level: 'RESTRICTED',
    template: 'expense_audit',
    split: 'TRAIN',
  },
  {
    text: 'Generate relocation expense authorization for engineer Priya Sharma relocating to Denver facility, allowance $22,500.',
    level: 'INTERNAL',
    template: 'payroll_accounting',
    split: 'TRAIN',
  },
  {
    text: 'The workers compensation insurance claim lists employee SSN 334-12-9081 and attending physician Dr. Howard Bell.',
    level: 'RESTRICTED',
    template: 'hr_medical',
    split: 'TRAIN',
  },
  {
    text: 'Archive performance appraisal for lead engineer Carlos Gomez: rating Exceeds Expectations, merit increase 7.5%.',
    level: 'CONFIDENTIAL',
    template: 'performance_review',
    split: 'TRAIN',
  },
  // DEV Split
  {
    text: 'Forward health insurance enrollment verification for employee badge NV-EMP-10294 to provider UnitedHealthcare.',
    level: 'CONFIDENTIAL',
    template: 'benefits_admin',
    split: 'DEV',
  },
  {
    text: 'Candidate reference check for Dr. Fiona Gallagher (phone: 650-555-4921) submitted positive feedback for flight dynamics.',
    level: 'INTERNAL',
    template: 'candidate_recruiting',
    split: 'DEV',
  },
  {
    text: 'Process wage garnishment notice for employee SSN 654-21-8890 received from Washington State Department of Revenue.',
    level: 'RESTRICTED',
    template: 'payroll_accounting',
    split: 'DEV',
  },
  {
    text: 'Draft offer letter for Senior Telemetry Specialist: Base salary $185,000, 20 days PTO, starting March 1st.',
    level: 'CONFIDENTIAL',
    template: 'candidate_recruiting',
    split: 'DEV',
  },
  {
    text: 'Verify passport number 982144701 for flight operations technician Bradley Cooper traveling to international test range.',
    level: 'RESTRICTED',
    template: 'security_clearance',
    split: 'DEV',
  },
];

// --- UNSEEN PII (TEST split strictly held-out) ---
const unseenPiiPrompts: Array<{
  text: string;
  level: SensitivityLevel;
  template: string;
}> = [
  {
    text: 'Please draft tax documents for candidate Zoe Zimmerman, SSN 198-44-3210, joining our optical payload engineering unit.',
    level: 'RESTRICTED',
    template: 'hr_onboarding_unseen',
  },
  {
    text: 'Verify identity of defense analyst Nathanial Drake: personal cellular +1-206-555-9832 and passport number Z7729104.',
    level: 'RESTRICTED',
    template: 'security_clearance_unseen',
  },
  {
    text: 'Draft termination notice and pension disbursement calculation for employee badge NV-EMP-99104 with 22 years service.',
    level: 'CONFIDENTIAL',
    template: 'hr_severance_unseen',
  },
  {
    text: 'Audit executive corporate jet manifest: Chief Technology Officer Victoria Vance (SSN 512-88-0091) traveled to Edwards AFB.',
    level: 'RESTRICTED',
    template: 'executive_travel_unseen',
  },
  {
    text: 'Process confidential mental health counseling reimbursement for employee badge NV-EMP-33109 under EAP program.',
    level: 'RESTRICTED',
    template: 'hr_medical_unseen',
  },
  {
    text: 'Direct deposit authorization for contractor Gregory House: Routing 021000021, Account 4401928371 at Chase Bank.',
    level: 'RESTRICTED',
    template: 'payroll_accounting_unseen',
  },
  {
    text: 'Prepare candidate NDA and drug screening consent form for applicant Liam OConnor, mobile phone 303-555-8822.',
    level: 'INTERNAL',
    template: 'candidate_recruiting_unseen',
  },
  {
    text: 'Emergency notification dispatched to spouse of injured technician: contact Mrs. Beverly Crusher at 415-555-1701.',
    level: 'CONFIDENTIAL',
    template: 'employee_directory_unseen',
  },
  {
    text: 'The confidential whistleblower report references senior director Anthony DiNozzo, badge NV-EMP-11002, regarding supplier kickbacks.',
    level: 'RESTRICTED',
    template: 'ethics_investigation_unseen',
  },
  {
    text: 'Summarize compensation committee resolution: VP Engineering base compensation revised to $320,000 plus performance bonus.',
    level: 'RESTRICTED',
    template: 'executive_compensation_unseen',
  },
];

// Add PII prompts
for (const p of seenPiiPrompts) {
  addRecord({
    text: p.text,
    gold_class: 'PII',
    sensitivity_level: p.level,
    entity_category: 'PII',
    terminology_group: 'pii_seen',
    seen_or_unseen: 'SEEN',
    template_family: p.template,
    split: p.split,
    hard_negative_group: null,
  });
}

for (const p of unseenPiiPrompts) {
  addRecord({
    text: p.text,
    gold_class: 'PII',
    sensitivity_level: p.level,
    entity_category: 'PII',
    terminology_group: 'pii_unseen',
    seen_or_unseen: 'UNSEEN',
    template_family: p.template,
    split: 'TEST',
    hard_negative_group: null,
  });
}

// =========================================================================
// 3. TARGET CLASS 2: SECRETS & CREDENTIALS
// API keys, private keys, database connection strings, JWT signing tokens
// =========================================================================

// --- SEEN CREDENTIALS (TRAIN & DEV) ---
const seenSecretPrompts: Array<{
  text: string;
  level: SensitivityLevel;
  template: string;
  split: 'TRAIN' | 'DEV';
}> = [
  {
    text: 'Connect to our internal PostgreSQL instance postgresql://nova_admin:ValkyrieSwarm2026!@core-telemetry.internal.novasystems.net:5432/telemetry_prod and run vacuum.',
    level: 'RESTRICTED',
    template: 'db_connection',
    split: 'TRAIN',
  },
  {
    text: 'Verify whether this AWS staging access key AKIA3NOVAENG77EXMPL is authorized to pull container images from ECR.',
    level: 'RESTRICTED',
    template: 'key_validation',
    split: 'TRAIN',
  },
  {
    text: 'The deployment script failed authentication. Please inspect GitHub access token ghp_NovASecureTokenDeployPipelineForSeenTrainingOnly.',
    level: 'RESTRICTED',
    template: 'ci_cd_deployment',
    split: 'TRAIN',
  },
  {
    text: 'Rotate our master HMAC signing secret: nova_sec_live_9981aef02c774b9d10e82c1109923bbd4a2 before the quarterly security audit.',
    level: 'RESTRICTED',
    template: 'secret_rotation',
    split: 'TRAIN',
  },
  {
    text: 'Here is our RSA Private Key for Aurora telemetry signing:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0tG7qXw...\n-----END RSA PRIVATE KEY-----\nPlease generate public cert.',
    level: 'RESTRICTED',
    template: 'key_validation',
    split: 'TRAIN',
  },
  {
    text: 'Export MongoDB connection URI: mongodb://clusterAdmin:AegisFlightKey99$@vault-01.mgmt.novasystems.net:27017/flight_records?authSource=admin.',
    level: 'RESTRICTED',
    template: 'db_connection',
    split: 'TRAIN',
  },
  {
    text: 'Test API endpoint authentication using bearer token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJub3ZhLWVuZyIsImFkbWluIjp0cnVlfQ.sampleSignatureSeen.',
    level: 'RESTRICTED',
    template: 'token_debugging',
    split: 'TRAIN',
  },
  {
    text: 'Set environment variable NOVA_STRIPE_SECRET_KEY=sk_test_demo_sample_token_not_live for telemetry billing portal integration.',
    level: 'RESTRICTED',
    template: 'env_configuration',
    split: 'TRAIN',
  },
  {
    text: 'Validate Slack webhook integration URL: https://hooks.slack.com/services/T00000000/B00000000/novaSecurityAlertsChannelSeenWebhookSecret.',
    level: 'CONFIDENTIAL',
    template: 'webhook_configuration',
    split: 'TRAIN',
  },
  {
    text: 'Our Redis caching cluster requires authentication string AUTH NovaSwarmCachePasswd#2026! on port 6379.',
    level: 'RESTRICTED',
    template: 'db_connection',
    split: 'TRAIN',
  },
  {
    text: 'Initialize HashiCorp Vault token: s.novaRootTokenVaultSeenTrain8819002 for unsealing flight telemetry keyrings.',
    level: 'RESTRICTED',
    template: 'secret_rotation',
    split: 'TRAIN',
  },
  {
    text: 'Check if this OpenAI API key is billed to engineering: sk-proj-novaSeenTestingPromptKeyForEvaluationPurposes001122.',
    level: 'RESTRICTED',
    template: 'key_validation',
    split: 'TRAIN',
  },
  {
    text: 'Configure SFTP automated export with password: user=aero_transfer, host=sftp.novasystems.net, pass=FlightDataBackup2026$.',
    level: 'RESTRICTED',
    template: 'backup_automation',
    split: 'TRAIN',
  },
  // DEV Split
  {
    text: 'Update Datadog API key in agent configuration: DD_API_KEY=nova_dd_api_seen_dev_key_448102973901a.',
    level: 'RESTRICTED',
    template: 'env_configuration',
    split: 'DEV',
  },
  {
    text: 'Inspect RabbitMQ AMQP connection string: amqp://nova_worker:SwarmQueueSecret99!@hpc-aurora.cluster.novasystems.net:5672/flight_vhost.',
    level: 'RESTRICTED',
    template: 'db_connection',
    split: 'DEV',
  },
  {
    text: 'Verify AWS Secret Access Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY for autonomous flight backup S3 bucket.',
    level: 'RESTRICTED',
    template: 'key_validation',
    split: 'DEV',
  },
  {
    text: 'The Grafana telemetry dashboard datasource auth token is glsa_novaTelemetryDevMetricsToken_8829104.',
    level: 'CONFIDENTIAL',
    template: 'token_debugging',
    split: 'DEV',
  },
];

// --- UNSEEN CREDENTIALS (TEST split strictly held-out) ---
const unseenSecretPrompts: Array<{
  text: string;
  level: SensitivityLevel;
  template: string;
}> = [
  {
    text: 'Authenticate to high-throughput laser telemetry cluster: postgresql://unseen_telemetry:ChimeraBeamPass909!@grid-quantum.internal.novasystems.net:5432/quantum_optics.',
    level: 'RESTRICTED',
    template: 'db_connection_unseen',
  },
  {
    text: 'Audit AWS production credentials for satellite constellation: AKIA5UNSEENHYPERION99 with secret key zZ819401/unseenLaserDownlinkKey.',
    level: 'RESTRICTED',
    template: 'key_validation_unseen',
  },
  {
    text: 'Verify internal microservice bearer token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJub3ZhLWNlcmJlcnVzLWdhdGV3YXkiLCJzdWIiOiJ1bnNlZW4ifQ.unseenSignature.',
    level: 'RESTRICTED',
    template: 'token_debugging_unseen',
  },
  {
    text: 'The Project Cerberus tactical mesh node private key is:\n-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIHY7...\n-----END EC PRIVATE KEY-----\nPush to edge secure enclave.',
    level: 'RESTRICTED',
    template: 'key_validation_unseen',
  },
  {
    text: 'Push firmware payload using GitHub deployment token: ghp_UnseenGitHubTokenForLaserConstellationRelease99812.',
    level: 'RESTRICTED',
    template: 'ci_cd_deployment_unseen',
  },
  {
    text: 'Configure production API key for satellite uplink gateway: nova_sec_live_unseen_hyperion_8819024871902bbff.',
    level: 'RESTRICTED',
    template: 'secret_rotation_unseen',
  },
  {
    text: 'Validate MySQL master replica connection: mysql://root:CerberusRootPass2026#@secure-broker.prod.novasystems.net:3306/classified_ledger.',
    level: 'RESTRICTED',
    template: 'db_connection_unseen',
  },
  {
    text: 'Update Twilio production alert secret: TWILIO_AUTH_TOKEN=unseen_twilio_token_901928401924801928401924 for field incident pages.',
    level: 'RESTRICTED',
    template: 'env_configuration_unseen',
  },
  {
    text: 'Review Kubernetes service account secret token: k8s_token_unseen_cluster_tactical_edge_node_09_novasystems_net.',
    level: 'RESTRICTED',
    template: 'token_debugging_unseen',
  },
  {
    text: 'The SSH host private key for edge station edge-node-09.tactical.novasystems.net is compromised and must be revoked immediately.',
    level: 'RESTRICTED',
    template: 'secret_rotation_unseen',
  },
];

// Add secret prompts
for (const p of seenSecretPrompts) {
  addRecord({
    text: p.text,
    gold_class: 'secrets',
    sensitivity_level: p.level,
    entity_category: 'CREDENTIAL',
    terminology_group: 'credentials_seen',
    seen_or_unseen: 'SEEN',
    template_family: p.template,
    split: p.split,
    hard_negative_group: null,
  });
}

for (const p of unseenSecretPrompts) {
  addRecord({
    text: p.text,
    gold_class: 'secrets',
    sensitivity_level: p.level,
    entity_category: 'CREDENTIAL',
    terminology_group: 'credentials_unseen',
    seen_or_unseen: 'UNSEEN',
    template_family: p.template,
    split: 'TEST',
    hard_negative_group: null,
  });
}

// =========================================================================
// 4. TARGET CLASS 3: INTERNAL IDENTIFIERS
// Jira issue keys, internal cluster hostnames, repository paths, hardware revisions
// =========================================================================

// --- SEEN INTERNAL IDENTIFIERS (TRAIN & DEV) ---
const seenInternalIdPrompts: Array<{
  text: string;
  level: SensitivityLevel;
  template: string;
  split: 'TRAIN' | 'DEV';
}> = [
  {
    text: 'Review pull request #142 on internal repository novasys-core/hyper-nav regarding Kalman filter convergence under GPS loss.',
    level: 'INTERNAL',
    template: 'code_review',
    split: 'TRAIN',
  },
  {
    text: 'Please check resolution status for Jira ticket NOVA-ENG-1042 filed by the guidance and navigation team.',
    level: 'INTERNAL',
    template: 'jira_triage',
    split: 'TRAIN',
  },
  {
    text: 'Deploy telemetry collector daemon to cluster node telemetry-worker-04.internal.novasystems.net on port 9090.',
    level: 'INTERNAL',
    template: 'cluster_management',
    split: 'TRAIN',
  },
  {
    text: 'The hardware revision NV-HW-REV3-B exhibits high clock drift on the FPGA crystal oscillator during thermal cycling.',
    level: 'INTERNAL',
    template: 'hardware_diagnostics',
    split: 'TRAIN',
  },
  {
    text: 'Assign security ticket NOVA-SEC-8821 regarding unauthorized sudo escalation on dev-cluster.internal.novasystems.net.',
    level: 'INTERNAL',
    template: 'jira_triage',
    split: 'TRAIN',
  },
  {
    text: 'Clone the repository novasys-sec/auth-broker and inspect the OAuth token introspection endpoint latency.',
    level: 'INTERNAL',
    template: 'code_review',
    split: 'TRAIN',
  },
  {
    text: 'Run network traceroute between vault-01.mgmt.novasystems.net and core-telemetry.internal.novasystems.net.',
    level: 'INTERNAL',
    template: 'cluster_management',
    split: 'TRAIN',
  },
  {
    text: 'Audit Jira epic NOVA-AERO-3419 for flight envelope boundary condition verification prior to static test firings.',
    level: 'INTERNAL',
    template: 'jira_triage',
    split: 'TRAIN',
  },
  {
    text: 'Verify hardware bill of materials for avionics module NV-CHIP-AURORA against component vendor delivery schedules.',
    level: 'INTERNAL',
    template: 'hardware_diagnostics',
    split: 'TRAIN',
  },
  {
    text: 'The Prometheus alerting rule on hpc-aurora.cluster.novasystems.net triggered high memory pressure on node 12.',
    level: 'INTERNAL',
    template: 'cluster_management',
    split: 'TRAIN',
  },
  {
    text: 'Merge hotfix branch fix/telemetry-packet-loss into main on repository novasys-avionics/telemetry-daemon.',
    level: 'INTERNAL',
    template: 'code_review',
    split: 'TRAIN',
  },
  {
    text: 'File an engineering change request for bracket mounting plate NV-MECH-BRK-881 to prevent vibrational fatigue.',
    level: 'INTERNAL',
    template: 'hardware_diagnostics',
    split: 'TRAIN',
  },
  // DEV Split
  {
    text: 'Resolve merge conflict in branch feature/nv-emp-sso in repository novasys-sec/auth-broker before sprint close.',
    level: 'INTERNAL',
    template: 'code_review',
    split: 'DEV',
  },
  {
    text: 'Check pending tasks in Jira sprint NOVA-SWARM-2026-Q1 regarding multi-agent formation collision avoidance.',
    level: 'INTERNAL',
    template: 'jira_triage',
    split: 'DEV',
  },
  {
    text: 'Reboot management interface on switch sw-core-01.mgmt.novasystems.net during the scheduled maintenance window.',
    level: 'INTERNAL',
    template: 'cluster_management',
    split: 'DEV',
  },
  {
    text: 'Update the schematic diagram for microcontroller breakout board NV-HW-REV3-C in Altium Designer format.',
    level: 'INTERNAL',
    template: 'hardware_diagnostics',
    split: 'DEV',
  },
];

// --- UNSEEN INTERNAL IDENTIFIERS (TEST split strictly held-out) ---
const unseenInternalIdPrompts: Array<{
  text: string;
  level: SensitivityLevel;
  template: string;
}> = [
  {
    text: 'Inspect commit history on repository novasys-optics/laser-downlink regarding beam steering closed-loop servo stability.',
    level: 'INTERNAL',
    template: 'code_review_unseen',
  },
  {
    text: 'Please prioritize Jira ticket NOVA-PAYLOAD-9011 regarding pulsed beam diode cooling jacket pressure drop.',
    level: 'INTERNAL',
    template: 'jira_triage_unseen',
  },
  {
    text: 'Provision new high-performance worker nodes on cluster grid-quantum.internal.novasystems.net for Monte Carlo flight simulations.',
    level: 'INTERNAL',
    template: 'cluster_management_unseen',
  },
  {
    text: 'The optical sensor package NV-SENSOR-S6 failed dark-current calibration in thermal chamber 3 at minus 40 Celsius.',
    level: 'INTERNAL',
    template: 'hardware_diagnostics_unseen',
  },
  {
    text: 'Clone internal repository novasys-payload/strike-core to analyze the arming sequence state machine transitions.',
    level: 'INTERNAL',
    template: 'code_review_unseen',
  },
  {
    text: 'Audit user access permissions on edge host secure-broker.prod.novasystems.net for external contractor accounts.',
    level: 'INTERNAL',
    template: 'cluster_management_unseen',
  },
  {
    text: 'Track bug report NOVA-OPTICS-2144 detailing adaptive optics wave-front sensor latency spikes during gimbal slew.',
    level: 'INTERNAL',
    template: 'jira_triage_unseen',
  },
  {
    text: 'Deploy container image novasys-edge/cerberus-mesh:v2.1 to remote tactical host edge-node-09.tactical.novasystems.net.',
    level: 'INTERNAL',
    template: 'cluster_management_unseen',
  },
  {
    text: 'Review circuit board layout revisions for experimental payload module NV-PAYLOAD-MOD4 before PCB fabrication order.',
    level: 'INTERNAL',
    template: 'hardware_diagnostics_unseen',
  },
  {
    text: 'Close incident ticket NOVA-DIR-5510 concerning telemetry packet checksum failures on tactical satellite links.',
    level: 'INTERNAL',
    template: 'jira_triage_unseen',
  },
];

// Add internal identifier prompts
for (const p of seenInternalIdPrompts) {
  addRecord({
    text: p.text,
    gold_class: 'internal identifiers',
    sensitivity_level: p.level,
    entity_category: 'INTERNAL_IDENTIFIER',
    terminology_group: 'nova_infra_seen',
    seen_or_unseen: 'SEEN',
    template_family: p.template,
    split: p.split,
    hard_negative_group: null,
  });
}

for (const p of unseenInternalIdPrompts) {
  addRecord({
    text: p.text,
    gold_class: 'internal identifiers',
    sensitivity_level: p.level,
    entity_category: 'INTERNAL_IDENTIFIER',
    terminology_group: 'nova_infra_unseen',
    seen_or_unseen: 'UNSEEN',
    template_family: p.template,
    split: 'TEST',
    hard_negative_group: null,
  });
}

// =========================================================================
// 5. TARGET CLASS 4: CONFIDENTIAL TECHNICAL & FINANCIAL INFORMATION
// Technical schemas, flight specs, algorithms, M&A valuations, earnings
// =========================================================================

// --- SEEN CONFIDENTIAL TECHNICAL & FINANCIAL (TRAIN & DEV) ---
const seenConfidentialPrompts: Array<{
  text: string;
  level: SensitivityLevel;
  category: 'CONFIDENTIAL_TECHNICAL' | 'CONFIDENTIAL_FINANCIAL';
  group: string;
  template: string;
  split: 'TRAIN' | 'DEV';
}> = [
  // Technical (Aurora, Valkyrie, Zephyr)
  {
    text: 'The Project Aurora hypersonic telemetry frame transmits Mach number, stagnation temperature, and pressure transducer values at 500 Hz.',
    level: 'CONFIDENTIAL',
    category: 'CONFIDENTIAL_TECHNICAL',
    group: 'aurora_technical_seen',
    template: 'telemetry_spec',
    split: 'TRAIN',
  },
  {
    text: 'Synthesize the aerodynamic heating dissipation model for Project Aurora during re-entry phase descent at Mach 6.4.',
    level: 'CONFIDENTIAL',
    category: 'CONFIDENTIAL_TECHNICAL',
    group: 'aurora_technical_seen',
    template: 'thermal_simulation',
    split: 'TRAIN',
  },
  {
    text: 'Explain how Valkyrie-X swarm routing calculates optimal target distribution without a centralized control coordinator.',
    level: 'RESTRICTED',
    category: 'CONFIDENTIAL_TECHNICAL',
    group: 'valkyrie_technical_seen',
    template: 'algorithm_explanation',
    split: 'TRAIN',
  },
  {
    text: 'The Valkyrie-X guidance law applies proportional navigation with adaptive line-of-sight rate filtering to counter target evasive maneuvers.',
    level: 'RESTRICTED',
    category: 'CONFIDENTIAL_TECHNICAL',
    group: 'valkyrie_technical_seen',
    template: 'algorithm_explanation',
    split: 'TRAIN',
  },
  {
    text: 'In Zephyr-OS, the proprietary microkernel enforces strict memory partitioning between flight-critical avionics and mission payloads.',
    level: 'CONFIDENTIAL',
    category: 'CONFIDENTIAL_TECHNICAL',
    group: 'zephyr_technical_seen',
    template: 'kernel_architecture',
    split: 'TRAIN',
  },
  {
    text: 'Analyze the zero-day vulnerability mitigation patch applied to Zephyr-OS inter-process message queues.',
    level: 'CONFIDENTIAL',
    category: 'CONFIDENTIAL_TECHNICAL',
    group: 'zephyr_technical_seen',
    template: 'kernel_architecture',
    split: 'TRAIN',
  },
  {
    text: 'Summarize flight test data from Aurora-V telemetry launch #7 regarding solid rocket booster separation jitter.',
    level: 'CONFIDENTIAL',
    category: 'CONFIDENTIAL_TECHNICAL',
    group: 'aurora_technical_seen',
    template: 'flight_test_summary',
    split: 'TRAIN',
  },
  {
    text: 'The autonomous obstacle avoidance heuristic in Valkyrie-X guarantees swarm separation distances of greater than 15 meters at 250 knots.',
    level: 'RESTRICTED',
    category: 'CONFIDENTIAL_TECHNICAL',
    group: 'valkyrie_technical_seen',
    template: 'algorithm_explanation',
    split: 'TRAIN',
  },
  // Financial (Apex, Corporate Financials)
  {
    text: 'The confidential Project Apex acquisition proposal includes a $35M retention pool for SkyLink Dynamics senior engineering talent.',
    level: 'RESTRICTED',
    category: 'CONFIDENTIAL_FINANCIAL',
    group: 'apex_financial_seen',
    template: 'm_and_a_valuation',
    split: 'TRAIN',
  },
  {
    text: 'Draft slide deck on NOVA Systems Q3 confidential gross margin targets: defense avionics margin forecast at 38.4%.',
    level: 'CONFIDENTIAL',
    category: 'CONFIDENTIAL_FINANCIAL',
    group: 'financial_planning_seen',
    template: 'financial_reporting',
    split: 'TRAIN',
  },
  {
    text: 'The Project Apex valuation model projects $45M annual recurring revenue synergies by integrating SkyLink ground stations into NOVA core.',
    level: 'RESTRICTED',
    category: 'CONFIDENTIAL_FINANCIAL',
    group: 'apex_financial_seen',
    template: 'm_and_a_valuation',
    split: 'TRAIN',
  },
  {
    text: 'Review executive board compensation minutes regarding stock option vesting accelerations triggered by Project Apex completion.',
    level: 'RESTRICTED',
    category: 'CONFIDENTIAL_FINANCIAL',
    group: 'apex_financial_seen',
    template: 'board_minutes',
    split: 'TRAIN',
  },
  {
    text: 'The confidential internal audit reveals a $3.2M budget overrun in the hypersonic propulsion prototype testing contract.',
    level: 'CONFIDENTIAL',
    category: 'CONFIDENTIAL_FINANCIAL',
    group: 'financial_planning_seen',
    template: 'financial_reporting',
    split: 'TRAIN',
  },
  {
    text: 'Analyze the proprietary competitive pricing matrix for the Pentagon unmanned swarm defense contract tender.',
    level: 'RESTRICTED',
    category: 'CONFIDENTIAL_FINANCIAL',
    group: 'defense_contract_seen',
    template: 'contract_bidding',
    split: 'TRAIN',
  },
  // DEV Split
  {
    text: 'Draft technical report on Project Aurora pitot-static tube heating elements to prevent ice accumulation at high altitude.',
    level: 'CONFIDENTIAL',
    category: 'CONFIDENTIAL_TECHNICAL',
    group: 'aurora_technical_seen',
    template: 'telemetry_spec',
    split: 'DEV',
  },
  {
    text: 'Review the confidential debt financing term sheet from Goldman Sachs backing the Project Apex corporate acquisition.',
    level: 'RESTRICTED',
    category: 'CONFIDENTIAL_FINANCIAL',
    group: 'apex_financial_seen',
    template: 'm_and_a_valuation',
    split: 'DEV',
  },
  {
    text: 'The Valkyrie-X inertial measurement unit calibration routine requires 120 seconds of stationary sensor drift accumulation.',
    level: 'RESTRICTED',
    category: 'CONFIDENTIAL_TECHNICAL',
    group: 'valkyrie_technical_seen',
    template: 'algorithm_explanation',
    split: 'DEV',
  },
  {
    text: 'Calculate the expected pro-forma free cash flow impact of the SkyLink acquisition in Project Apex for fiscal year 2027.',
    level: 'RESTRICTED',
    category: 'CONFIDENTIAL_FINANCIAL',
    group: 'apex_financial_seen',
    template: 'm_and_a_valuation',
    split: 'DEV',
  },
];

// --- UNSEEN CONFIDENTIAL TECHNICAL & FINANCIAL (TEST split strictly held-out) ---
const unseenConfidentialPrompts: Array<{
  text: string;
  level: SensitivityLevel;
  category: 'CONFIDENTIAL_TECHNICAL' | 'CONFIDENTIAL_FINANCIAL';
  group: string;
  template: string;
}> = [
  // Technical (Chimera, Hyperion, Cerberus, Sentinel-6)
  {
    text: 'Project Chimera solid-state laser cavity achieves 150 kilowatt beam output with active dielectric liquid cooling loops.',
    level: 'RESTRICTED',
    category: 'CONFIDENTIAL_TECHNICAL',
    group: 'chimera_technical_unseen',
    template: 'laser_physics_unseen',
  },
  {
    text: 'Analyze the beam jitter stabilization algorithm in Project Chimera utilizing fast steering mirrors at 2.5 kHz bandwidth.',
    level: 'RESTRICTED',
    category: 'CONFIDENTIAL_TECHNICAL',
    group: 'chimera_technical_unseen',
    template: 'laser_physics_unseen',
  },
  {
    text: 'The Project Hyperion space-to-ground optical communications link uses dual-polarization quadrature phase shift keying modulation.',
    level: 'CONFIDENTIAL',
    category: 'CONFIDENTIAL_TECHNICAL',
    group: 'hyperion_technical_unseen',
    template: 'optical_downlink_unseen',
  },
  {
    text: 'Synthesize the atmospheric turbulence phase compensation matrix for the Project Hyperion optical ground receiving telescope.',
    level: 'CONFIDENTIAL',
    category: 'CONFIDENTIAL_TECHNICAL',
    group: 'hyperion_technical_unseen',
    template: 'optical_downlink_unseen',
  },
  {
    text: 'Project Cerberus microsegmentation architecture dynamically isolates compromised tactical nodes within 200 microseconds of anomaly detection.',
    level: 'CONFIDENTIAL',
    category: 'CONFIDENTIAL_TECHNICAL',
    group: 'cerberus_technical_unseen',
    template: 'zero_trust_mesh_unseen',
  },
  {
    text: 'The Sentinel-6 sensor fusion algorithm merges synthetic aperture radar Doppler returns with infrared focal plane imagery for low-observable track generation.',
    level: 'CONFIDENTIAL',
    category: 'CONFIDENTIAL_TECHNICAL',
    group: 'sentinel_technical_unseen',
    template: 'sensor_fusion_unseen',
  },
  // Financial (Talon, Unannounced Corporate Financials)
  {
    text: 'The Project Talon confidential takeover valuation allocates $88M cash to purchase 100% of AeroPrecision Corp shares.',
    level: 'RESTRICTED',
    category: 'CONFIDENTIAL_FINANCIAL',
    group: 'talon_financial_unseen',
    template: 'm_and_a_unseen',
  },
  {
    text: 'Prepare financial sensitivity tables modeling Project Talon EPS accretion under conservative vs aggressive synergy assumptions.',
    level: 'RESTRICTED',
    category: 'CONFIDENTIAL_FINANCIAL',
    group: 'talon_financial_unseen',
    template: 'm_and_a_unseen',
  },
  {
    text: 'The confidential Q4 board packet forecasts defense contract backlog reaching $420M driven by international satellite orders.',
    level: 'CONFIDENTIAL',
    category: 'CONFIDENTIAL_FINANCIAL',
    group: 'board_financials_unseen',
    template: 'financial_reporting_unseen',
  },
  {
    text: 'Review the confidential tax haven structuring analysis for European distribution of Project Hyperion ground terminals.',
    level: 'CONFIDENTIAL',
    category: 'CONFIDENTIAL_FINANCIAL',
    group: 'tax_planning_unseen',
    template: 'financial_reporting_unseen',
  },
];

// Add confidential prompts
for (const p of seenConfidentialPrompts) {
  addRecord({
    text: p.text,
    gold_class: 'confidential technical/financial information',
    sensitivity_level: p.level,
    entity_category: p.category,
    terminology_group: p.group,
    seen_or_unseen: 'SEEN',
    template_family: p.template,
    split: p.split,
    hard_negative_group: null,
  });
}

for (const p of unseenConfidentialPrompts) {
  addRecord({
    text: p.text,
    gold_class: 'confidential technical/financial information',
    sensitivity_level: p.level,
    entity_category: p.category,
    terminology_group: p.group,
    seen_or_unseen: 'UNSEEN',
    template_family: p.template,
    split: 'TEST',
    hard_negative_group: null,
  });
}

// =========================================================================
// 6. TARGET CLASS 5: BENIGN GENERAL EMPLOYEE PROMPTS
// Coding, documentation, math, general science, HR policy inquiries
// =========================================================================

// --- SEEN BENIGN (TRAIN & DEV) ---
const seenBenignPrompts: Array<{
  text: string;
  template: string;
  split: 'TRAIN' | 'DEV';
}> = [
  {
    text: 'How do I optimize a React useEffect dependency array to prevent unnecessary network re-fetches?',
    template: 'code_optimization',
    split: 'TRAIN',
  },
  {
    text: 'Explain the difference between interface and type aliases in TypeScript with practical examples.',
    template: 'programming_concept',
    split: 'TRAIN',
  },
  {
    text: 'What are the best practices for containerizing a Node.js microservice using multi-stage Docker builds?',
    template: 'devops_architecture',
    split: 'TRAIN',
  },
  {
    text: 'How does the Raft consensus algorithm handle leader election when split votes occur?',
    template: 'distributed_systems',
    split: 'TRAIN',
  },
  {
    text: 'Write a Python function using pandas to compute rolling 7-day average sales from a time-series dataframe.',
    template: 'data_analysis',
    split: 'TRAIN',
  },
  {
    text: 'What is the standard company holiday schedule for Labor Day and Thanksgiving in our employee handbook?',
    template: 'general_hr_policy',
    split: 'TRAIN',
  },
  {
    text: 'Please review this Markdown document for grammatical errors, passive voice, and clarity.',
    template: 'writing_assistance',
    split: 'TRAIN',
  },
  {
    text: 'Explain the mathematical relationship between signal-to-noise ratio and bit error rate in QAM modulation.',
    template: 'engineering_math',
    split: 'TRAIN',
  },
  {
    text: 'How do I configure nginx to act as a reverse proxy with SSL termination and HTTP/2 support?',
    template: 'devops_architecture',
    split: 'TRAIN',
  },
  {
    text: 'What is the difference between Git merge and Git rebase when working on feature branches with a team?',
    template: 'git_workflow',
    split: 'TRAIN',
  },
  {
    text: 'Write a Rust function that safely parses an integer from a string slice without panicking on invalid input.',
    template: 'programming_concept',
    split: 'TRAIN',
  },
  {
    text: 'How do I set up Prometheus alerting rules to detect disk saturation when available space drops below 15%?',
    template: 'devops_architecture',
    split: 'TRAIN',
  },
  {
    text: 'Summarize the key principles of test-driven development (TDD) and its impact on code maintainability.',
    template: 'software_engineering',
    split: 'TRAIN',
  },
  {
    text: 'What is the difference between row-oriented and columnar database storage formats like Parquet?',
    template: 'database_design',
    split: 'TRAIN',
  },
  {
    text: 'Provide a checklist for conducting a productive 30-minute sprint retrospective meeting with remote engineers.',
    template: 'agile_process',
    split: 'TRAIN',
  },
  // DEV Split
  {
    text: 'Explain how CSS grid layout fr units calculate remaining space compared to flexbox flex-grow.',
    template: 'frontend_web',
    split: 'DEV',
  },
  {
    text: 'How does an operating system kernel handle context switches between user-space threads and kernel threads?',
    template: 'os_internals',
    split: 'DEV',
  },
  {
    text: 'What are the trade-offs between optimistic locking and pessimistic locking in relational databases?',
    template: 'database_design',
    split: 'DEV',
  },
  {
    text: 'Draft an email thanking a guest speaker for presenting an educational seminar on quantum computing basics.',
    template: 'writing_assistance',
    split: 'DEV',
  },
  {
    text: 'How do I calculate the Nyquist Shannon sampling rate required to digitize an audio signal up to 22 kHz?',
    template: 'engineering_math',
    split: 'DEV',
  },
];

// --- UNSEEN BENIGN (TEST split strictly held-out) ---
const unseenBenignPrompts: Array<{
  text: string;
  template: string;
}> = [
  {
    text: 'Explain how the Transformer self-attention mechanism scales quadratically with input sequence length.',
    template: 'machine_learning_concepts',
  },
  {
    text: 'What are the thermodynamic differences between Brayton cycle and Rankine cycle heat engines?',
    template: 'mechanical_engineering',
  },
  {
    text: 'How do I configure PostgreSQL streaming replication between a primary and read replica using repmgr?',
    template: 'database_administration_unseen',
  },
  {
    text: 'Write an algorithm in C++ to find the strongly connected components of a directed graph using Tarjans method.',
    template: 'algorithms_unseen',
  },
  {
    text: 'What are the main aerodynamic design features of supercritical airfoils that delay transonic wave drag?',
    template: 'aerodynamics_unseen',
  },
  {
    text: 'How does the IEEE 802.11ax Wi-Fi 6 standard utilize OFDMA to improve multi-user throughput efficiency?',
    template: 'telecommunications_unseen',
  },
  {
    text: 'Explain the principles of zero-knowledge proofs and how zk-SNARKs enable verifiable computation without data disclosure.',
    template: 'cryptography_theory_unseen',
  },
  {
    text: 'What is the role of the cerebellum in fine motor coordination and balance in human neuroanatomy?',
    template: 'biology_science_unseen',
  },
  {
    text: 'Draft a polite response to a vendor requesting an extension on an RFP submission deadline by two business days.',
    template: 'vendor_management_unseen',
  },
  {
    text: 'How does the Linux epoll system call achieve O(1) event notification compared to select and poll?',
    template: 'os_internals_unseen',
  },
];

// Add benign prompts
for (const p of seenBenignPrompts) {
  addRecord({
    text: p.text,
    gold_class: 'benign',
    sensitivity_level: 'PUBLIC',
    entity_category: 'BENIGN',
    terminology_group: 'general_tech_seen',
    seen_or_unseen: 'SEEN',
    template_family: p.template,
    split: p.split,
    hard_negative_group: null,
  });
}

for (const p of unseenBenignPrompts) {
  addRecord({
    text: p.text,
    gold_class: 'benign',
    sensitivity_level: 'PUBLIC',
    entity_category: 'BENIGN',
    terminology_group: 'general_tech_unseen',
    seen_or_unseen: 'UNSEEN',
    template_family: p.template,
    split: 'TEST',
    hard_negative_group: null,
  });
}

// =========================================================================
// 7. MULTI-CATEGORY EXAMPLES
// Prompts combining two distinct sensitive domains:
// - PII + Internal Identifier
// - Credential + Confidential Technical
// - Internal Identifier + Confidential Financial
// - Credential + PII
// =========================================================================

const multiCategoryPrompts: Array<{
  text: string;
  primaryClass: GoldClass;
  level: SensitivityLevel;
  seen: 'SEEN' | 'UNSEEN';
  split: 'TRAIN' | 'DEV' | 'TEST';
  template: string;
  group: string;
}> = [
  // SEEN Multi-Category (TRAIN & DEV)
  {
    text: 'Employee Sarah Jenkins (SSN 452-98-1124) submitted code changes for Project Aurora to repository novasys-core/hyper-nav.',
    primaryClass: 'PII',
    level: 'RESTRICTED',
    seen: 'SEEN',
    split: 'TRAIN',
    template: 'multi_pii_and_identifier',
    group: 'multi_seen_01',
  },
  {
    text: 'Configure database connection postgresql://nova_admin:ValkyrieSwarm2026!@core-telemetry.internal.novasystems.net:5432/telemetry_prod to ingest Project Aurora telemetry data.',
    primaryClass: 'secrets',
    level: 'RESTRICTED',
    seen: 'SEEN',
    split: 'TRAIN',
    template: 'multi_secret_and_technical',
    group: 'multi_seen_02',
  },
  {
    text: 'Assign Jira ticket NOVA-ENG-1042 to assess financial cost overrun of $1.4M on the Project Apex acquisition due diligence.',
    primaryClass: 'confidential technical/financial information',
    level: 'RESTRICTED',
    seen: 'SEEN',
    split: 'TRAIN',
    template: 'multi_identifier_and_financial',
    group: 'multi_seen_03',
  },
  {
    text: 'Check if lead architect Marcus Vance (cell: +1-312-555-8921) authorized AWS access key AKIA3NOVAENG77EXMPL for cloud telemetry sync.',
    primaryClass: 'secrets',
    level: 'RESTRICTED',
    seen: 'SEEN',
    split: 'TRAIN',
    template: 'multi_secret_and_pii',
    group: 'multi_seen_04',
  },
  {
    text: 'Upload Zephyr-OS kernel panic dump for employee badge NV-EMP-88213 to vault-01.mgmt.novasystems.net.',
    primaryClass: 'internal identifiers',
    level: 'CONFIDENTIAL',
    seen: 'SEEN',
    split: 'DEV',
    template: 'multi_pii_and_identifier',
    group: 'multi_seen_05',
  },
  {
    text: 'The financial compensation review for VP Robert Sterling references Jira issue NOVA-SEC-8821 regarding corporate card audit.',
    primaryClass: 'PII',
    level: 'RESTRICTED',
    seen: 'SEEN',
    split: 'DEV',
    template: 'multi_pii_and_financial',
    group: 'multi_seen_06',
  },

  // UNSEEN Multi-Category (TEST split strictly held-out)
  {
    text: 'Candidate Zoe Zimmerman (SSN 198-44-3210) was assigned Jira issue NOVA-PAYLOAD-9011 to review Project Chimera laser cavity schematics.',
    primaryClass: 'PII',
    level: 'RESTRICTED',
    seen: 'UNSEEN',
    split: 'TEST',
    template: 'multi_pii_and_technical_unseen',
    group: 'multi_unseen_01',
  },
  {
    text: 'Connect with secret key zZ819401/unseenLaserDownlinkKey to grid-quantum.internal.novasystems.net to download Project Hyperion optical frame specs.',
    primaryClass: 'secrets',
    level: 'RESTRICTED',
    seen: 'UNSEEN',
    split: 'TEST',
    template: 'multi_secret_and_technical_unseen',
    group: 'multi_unseen_02',
  },
  {
    text: 'Review repository novasys-payload/strike-core containing the $88M Project Talon tender valuation and antitrust risk analysis.',
    primaryClass: 'confidential technical/financial information',
    level: 'RESTRICTED',
    seen: 'UNSEEN',
    split: 'TEST',
    template: 'multi_identifier_and_financial_unseen',
    group: 'multi_unseen_03',
  },
  {
    text: 'Defense analyst Nathanial Drake (passport Z7729104) uploaded Project Cerberus mesh configuration to secure-broker.prod.novasystems.net.',
    primaryClass: 'PII',
    level: 'RESTRICTED',
    seen: 'UNSEEN',
    split: 'TEST',
    template: 'multi_pii_and_identifier_unseen',
    group: 'multi_unseen_04',
  },
];

for (const p of multiCategoryPrompts) {
  addRecord({
    text: p.text,
    gold_class: p.primaryClass,
    sensitivity_level: p.level,
    entity_category: 'MULTI_CATEGORY',
    terminology_group: p.group,
    seen_or_unseen: p.seen,
    template_family: p.template,
    split: p.split,
    hard_negative_group: null,
  });
}

// =========================================================================
// 8. PARAPHRASED FAMILIES (SYNTACTIC DIVERSITY & LEAKAGE CONTROL)
// Each family contains 4-5 diverse syntactic variants (question, imperative, debug, audit, summary)
// Crucially: Every family is assigned ENTIRELY to a single split!
// =========================================================================

interface ParaphraseFamilyDef {
  familyId: string;
  goldClass: GoldClass;
  level: SensitivityLevel;
  category: string;
  termGroup: string;
  seen: 'SEEN' | 'UNSEEN';
  split: 'TRAIN' | 'DEV' | 'TEST';
  variants: string[];
}

const paraphraseFamilies: ParaphraseFamilyDef[] = [
  // Family 1: Project Aurora Hypersonic Mach Telemetry (TRAIN)
  {
    familyId: 'PARA-AURORA-TELEMETRY',
    goldClass: 'confidential technical/financial information',
    level: 'CONFIDENTIAL',
    category: 'CONFIDENTIAL_TECHNICAL',
    termGroup: 'aurora_flight_seen',
    seen: 'SEEN',
    split: 'TRAIN',
    variants: [
      'What is the maximum Mach sampling rate supported by the Project Aurora flight telemetry bus?',
      'Please extract the Mach number calibration curve from the Project Aurora telemetry specifications.',
      'Debug the timestamp synchronization jitter on the Project Aurora hypersonic telemetry channel.',
      'Summarize the telemetry downlink bandwidth allocation table for Project Aurora stage 1 tests.',
      'We need to verify if the Project Aurora Mach sensor data matches the wind-tunnel calibration file.',
    ],
  },
  // Family 2: Valkyrie-X Collision Avoidance Heuristic (TRAIN)
  {
    familyId: 'PARA-VALKYRIE-COLLISION',
    goldClass: 'confidential technical/financial information',
    level: 'RESTRICTED',
    category: 'CONFIDENTIAL_TECHNICAL',
    termGroup: 'valkyrie_guidance_seen',
    seen: 'SEEN',
    split: 'TRAIN',
    variants: [
      'How does the Valkyrie-X swarm algorithm calculate collision avoidance vectors between adjacent UAVs?',
      'Optimize the Valkyrie-X collision avoidance math routine to run within a 10 millisecond control cycle.',
      'Can you explain the potential edge cases in the Valkyrie-X collision avoidance distance threshold logic?',
      'Draft an engineering specification for the decentralized collision avoidance protocol used in Valkyrie-X.',
      'Review the pull request adjusting the safety bubble radius in the Valkyrie-X swarm collision avoidance module.',
    ],
  },
  // Family 3: Zephyr-OS Secure Boot Integrity (TRAIN)
  {
    familyId: 'PARA-ZEPHYR-BOOT',
    goldClass: 'confidential technical/financial information',
    level: 'CONFIDENTIAL',
    category: 'CONFIDENTIAL_TECHNICAL',
    termGroup: 'zephyr_kernel_seen',
    seen: 'SEEN',
    split: 'TRAIN',
    variants: [
      'Explain the cryptographic root of trust verification sequence during Zephyr-OS secure boot.',
      'Troubleshoot the bootloader signature verification failure occurring on Zephyr-OS revision 4.2.',
      'What hardware security module commands are invoked during the Zephyr-OS secure boot validation?',
      'Document the stage 1 and stage 2 boot integrity chain implemented across our Zephyr-OS devices.',
      'Is the Zephyr-OS secure boot measurement register properly sealed into the onboard TPM 2.0 chip?',
    ],
  },
  // Family 4: Project Apex Synergy Valuation (TRAIN)
  {
    familyId: 'PARA-APEX-VALUATION',
    goldClass: 'confidential technical/financial information',
    level: 'RESTRICTED',
    category: 'CONFIDENTIAL_FINANCIAL',
    termGroup: 'apex_m_and_a_seen',
    seen: 'SEEN',
    split: 'TRAIN',
    variants: [
      'What are the core financial synergy assumptions underlying the $140M Project Apex acquisition model?',
      'Calculate the discounted cash flow sensitivity of the Project Apex acquisition under 12% vs 15% discount rates.',
      'Summarize the cost reduction milestones outlined in the confidential Project Apex post-merger integration plan.',
      'Does the Project Apex financial model account for SkyLink Dynamics pending patent litigation liabilities?',
      'Draft an executive summary of the Project Apex enterprise valuation for the board of directors audit committee.',
    ],
  },
  // Family 5: Jira Ticket NOVA-ENG-1042 Triage (DEV)
  {
    familyId: 'PARA-JIRA-1042',
    goldClass: 'internal identifiers',
    level: 'INTERNAL',
    category: 'INTERNAL_IDENTIFIER',
    termGroup: 'nova_infra_seen',
    seen: 'SEEN',
    split: 'DEV',
    variants: [
      'What is the current blocking status and assigned engineer for Jira ticket NOVA-ENG-1042?',
      'Update the sprint estimate on Jira issue NOVA-ENG-1042 from 5 story points to 8 story points.',
      'Summarize the root cause investigation comments posted yesterday on ticket NOVA-ENG-1042.',
      'Please add the avionics QA team as watchers to Jira issue NOVA-ENG-1042.',
      'Export the activity audit trail and attachment metadata for engineering issue NOVA-ENG-1042.',
    ],
  },
  // Family 6: Internal Cluster Core-Telemetry (DEV)
  {
    familyId: 'PARA-HOST-CORE-TELEMETRY',
    goldClass: 'internal identifiers',
    level: 'INTERNAL',
    category: 'INTERNAL_IDENTIFIER',
    termGroup: 'nova_infra_seen',
    seen: 'SEEN',
    split: 'DEV',
    variants: [
      'What is the current CPU utilization and memory consumption on core-telemetry.internal.novasystems.net?',
      'Generate an SSH config entry to tunnel metrics through bastion host to core-telemetry.internal.novasystems.net.',
      'Why is Prometheus failing to scrape the telemetry daemon running on core-telemetry.internal.novasystems.net?',
      'Verify the TLS certificate expiration date for the web endpoint on core-telemetry.internal.novasystems.net.',
      'Schedule a kernel security reboot for telemetry server core-telemetry.internal.novasystems.net this Saturday.',
    ],
  },
  // Family 7: Project Chimera Thermal Management (TEST - strictly held out)
  {
    familyId: 'PARA-CHIMERA-THERMAL',
    goldClass: 'confidential technical/financial information',
    level: 'RESTRICTED',
    category: 'CONFIDENTIAL_TECHNICAL',
    termGroup: 'chimera_payload_unseen',
    seen: 'UNSEEN',
    split: 'TEST',
    variants: [
      'How does the Project Chimera directed energy emitter handle thermal dissipation during continuous pulsing?',
      'Calculate the heat exchanger coolant flow rate needed to keep Project Chimera optics below 60 degrees Celsius.',
      'Analyze the thermal shock risk to the optical lenses during emergency Project Chimera shutdown sequences.',
      'What are the critical thermal failure thresholds defined in the Project Chimera payload engineering manual?',
      'Draft a simulation script in Python to model the heat dissipation curve of the Project Chimera pulse generator.',
    ],
  },
  // Family 8: Project Hyperion Ground Station Downlink (TEST - strictly held out)
  {
    familyId: 'PARA-HYPERION-DOWNLINK',
    goldClass: 'confidential technical/financial information',
    level: 'CONFIDENTIAL',
    category: 'CONFIDENTIAL_TECHNICAL',
    termGroup: 'hyperion_downlink_unseen',
    seen: 'UNSEEN',
    split: 'TEST',
    variants: [
      'What is the optical link budget margin for Project Hyperion under cloudy tropospheric conditions?',
      'Summarize the ground station tracking handover protocol used by Project Hyperion low Earth orbit satellites.',
      'Troubleshoot the bit error rate degradation observed during the Project Hyperion 40 Gbps downlink demonstration.',
      'How does Project Hyperion synchronize laser frequency offsets between the satellite beacon and ground receiver?',
      'Review the proprietary adaptive optics phase control loop implemented in the Project Hyperion terminal.',
    ],
  },
  // Family 9: Project Cerberus Edge Firewall Routing (TEST - strictly held out)
  {
    familyId: 'PARA-CERBERUS-ROUTING',
    goldClass: 'confidential technical/financial information',
    level: 'CONFIDENTIAL',
    category: 'CONFIDENTIAL_TECHNICAL',
    termGroup: 'cerberus_gateway_unseen',
    seen: 'UNSEEN',
    split: 'TEST',
    variants: [
      'How does Project Cerberus prevent lateral network traversal when an edge drone node is captured in the field?',
      'Explain the cryptographic handshaking used by Project Cerberus to authenticate ad-hoc tactical ground stations.',
      'Optimize the eBPF packet filter rules configured inside the Project Cerberus microsegmentation agent.',
      'Does Project Cerberus maintain encrypted audit trails when network connectivity to central command is severed?',
      'Draft a zero-trust network policy rule for Project Cerberus restricting outbound UDP telemetry ports.',
    ],
  },
  // Family 10: Project Talon Hostile Tender Bid (TEST - strictly held out)
  {
    familyId: 'PARA-TALON-TAKEOVER',
    goldClass: 'confidential technical/financial information',
    level: 'RESTRICTED',
    category: 'CONFIDENTIAL_FINANCIAL',
    termGroup: 'talon_m_and_a_unseen',
    seen: 'UNSEEN',
    split: 'TEST',
    variants: [
      'What is the premium over market capitalization offered in the confidential Project Talon tender bid?',
      'Analyze the regulatory antitrust filing requirements for Project Talon under Hart-Scott-Rodino regulations.',
      'How will NOVA Systems finance the $88M cash portion of the Project Talon acquisition proposal?',
      'Summarize the key defense customer contracts currently held by AeroPrecision that justify Project Talon.',
      'Draft an internal risk matrix evaluating hostile defense takeover countermeasures against Project Talon.',
    ],
  },
];

for (const fam of paraphraseFamilies) {
  for (const text of fam.variants) {
    addRecord({
      text,
      gold_class: fam.goldClass,
      sensitivity_level: fam.level,
      entity_category: fam.category,
      terminology_group: fam.termGroup,
      seen_or_unseen: fam.seen,
      template_family: fam.familyId,
      split: fam.split,
      hard_negative_group: null,
    });
  }
}

// =========================================================================
// 9. PROGRAMMATIC SCALE EXPANSION (DIVERSE TEMPLATES & FIXED SEED)
// To reach our target size of 400-450 prompts with balanced class and split distribution.
// =========================================================================

// --- Expanded Seen Prompts for TRAIN ---
const seenCodeEntities = [
  { name: 'Aurora-V', domain: 'flight controller telemetry', cat: 'CONFIDENTIAL_TECHNICAL', cls: 'confidential technical/financial information', lvl: 'CONFIDENTIAL' as SensitivityLevel },
  { name: 'Valkyrie-X', domain: 'swarm consensus trajectory', cat: 'CONFIDENTIAL_TECHNICAL', cls: 'confidential technical/financial information', lvl: 'RESTRICTED' as SensitivityLevel },
  { name: 'Zephyr-OS', domain: 'avionics RTOS memory manager', cat: 'CONFIDENTIAL_TECHNICAL', cls: 'confidential technical/financial information', lvl: 'CONFIDENTIAL' as SensitivityLevel },
];

const seenInfraHosts = [
  'core-telemetry.internal.novasystems.net',
  'vault-01.mgmt.novasystems.net',
  'hpc-aurora.cluster.novasystems.net',
  'dev-cluster.internal.novasystems.net',
  'api-gateway.corp.novasystems.net',
  'build-runner-04.ci.novasystems.net',
];

const seenRepos = [
  'novasys-core/hyper-nav',
  'novasys-sec/auth-broker',
  'novasys-avionics/telemetry-daemon',
  'novasys-swarm/consensus-mesh',
  'novasys-embedded/boot-firmware',
];

const seenJiraPrefixes = ['NOVA-ENG', 'NOVA-SEC', 'NOVA-AERO', 'NOVA-SWARM', 'NOVA-OPS'];

// Generate diverse TRAIN prompts
for (let i = 0; i < 90; i++) {
  const mode = i % 5;
  if (mode === 0) {
    // Technical / Codenames
    const ent = seenCodeEntities[i % seenCodeEntities.length];
    const verbs = ['Refactor', 'Profile performance for', 'Implement unit tests for', 'Document memory layout of', 'Audit concurrency lock in'];
    const v = verbs[Math.floor(rng() * verbs.length)];
    addRecord({
      text: `${v} the ${ent.name} ${ent.domain} routine to prevent telemetry pipeline starvation during high G-force maneuvers.`,
      gold_class: ent.cls as GoldClass,
      sensitivity_level: ent.lvl,
      entity_category: ent.cat,
      terminology_group: `${ent.name.toLowerCase()}_scaled_seen`,
      seen_or_unseen: 'SEEN',
      template_family: 'programmatic_tech_train',
      split: 'TRAIN',
      hard_negative_group: null,
    });
  } else if (mode === 1) {
    // Internal Identifiers: Hosts & Repos
    const host = choice(seenInfraHosts);
    const repo = choice(seenRepos);
    const action = choice(['Check TLS cipher suite on', 'Deploy updated binaries from repository', 'Audit access logs on', 'Inspect Prometheus metrics on', 'Review docker-compose file on']);
    addRecord({
      text: `${action} ${host} when building from branch release/2026 in repository ${repo}.`,
      gold_class: 'internal identifiers',
      sensitivity_level: 'INTERNAL',
      entity_category: 'INTERNAL_IDENTIFIER',
      terminology_group: 'nova_infra_scaled_seen',
      seen_or_unseen: 'SEEN',
      template_family: 'programmatic_infra_train',
      split: 'TRAIN',
      hard_negative_group: null,
    });
  } else if (mode === 2) {
    // Internal Identifiers: Jira
    const pfx = choice(seenJiraPrefixes);
    const num = 1000 + Math.floor(rng() * 8999);
    const issueKey = `${pfx}-${num}`;
    const topics = [
      'battery degradation under low atmospheric pressure',
      'can-bus message frame collision on auxiliary flight computer',
      'attitude determination Kalman filter gyro drift compensation',
      'unauthorized privilege escalation via legacy sudoers configuration',
      'thermal dissipation in solid-state motor power converters',
    ];
    const t = choice(topics);
    addRecord({
      text: `Review the acceptance criteria and attached trace logs for Jira ticket ${issueKey} regarding ${t}.`,
      gold_class: 'internal identifiers',
      sensitivity_level: 'INTERNAL',
      entity_category: 'INTERNAL_IDENTIFIER',
      terminology_group: 'nova_jira_scaled_seen',
      seen_or_unseen: 'SEEN',
      template_family: 'programmatic_jira_train',
      split: 'TRAIN',
      hard_negative_group: null,
    });
  } else if (mode === 3) {
    // PII: Employee / Personnel operations
    const firstNames = ['Alexander', 'Sophia', 'Benjamin', 'Emily', 'Daniel', 'Olivia', 'James', 'Mia'];
    const lastNames = ['Kowalski', 'Nakamura', 'Olsen', 'Dubois', 'Castillo', 'Lindqvist', 'Al-Mansoor', 'Patel'];
    const fn = choice(firstNames);
    const ln = choice(lastNames);
    const ssn3 = Math.floor(100 + rng() * 899);
    const ssn2 = Math.floor(10 + rng() * 89);
    const ssn4 = Math.floor(1000 + rng() * 8999);
    const ssn = `${ssn3}-${ssn2}-${ssn4}`;
    const roles = ['senior avionics technician', 'flight test telemetry analyst', 'cyber defense engineer', 'propulsion thermal specialist'];
    const r = choice(roles);
    addRecord({
      text: `Update personnel file for ${fn} ${ln} (SSN ${ssn}), serving as ${r}, regarding completed security briefing documentation.`,
      gold_class: 'PII',
      sensitivity_level: 'RESTRICTED',
      entity_category: 'PII',
      terminology_group: 'pii_scaled_seen',
      seen_or_unseen: 'SEEN',
      template_family: 'programmatic_pii_train',
      split: 'TRAIN',
      hard_negative_group: null,
    });
  } else {
    // Benign: General Software & Math questions
    const generalQueries = [
      'Write a Python generator function to stream large JSON files chunk by chunk to minimize memory overhead.',
      'Explain how the B-tree data structure maintains balanced search operations in relational database indices.',
      'What are the advantages of using WebAssembly for computationally intensive image processing in browser clients?',
      'How does the TCP congestion control algorithm Cubic differ from Reno during packet loss recovery?',
      'Provide an example of using the State design pattern in C++ to model a protocol parser state machine.',
      'What is the difference between CPU cache line bouncing and false sharing in multi-threaded programming?',
      'Explain the concept of monads in functional programming languages like Haskell with simple analogies.',
      'How do I calculate the eigenvalues and eigenvectors of a symmetric 3x3 matrix by hand?',
      'What are the best practices for structuring an Express.js application with TypeScript and middleware layers?',
      'Summarize the differences between synchronous and asynchronous logging frameworks in high-throughput applications.',
    ];
    addRecord({
      text: choice(generalQueries),
      gold_class: 'benign',
      sensitivity_level: 'PUBLIC',
      entity_category: 'BENIGN',
      terminology_group: 'general_tech_scaled_seen',
      seen_or_unseen: 'SEEN',
      template_family: 'programmatic_benign_train',
      split: 'TRAIN',
      hard_negative_group: null,
    });
  }
}

// Generate diverse DEV prompts (35 prompts)
for (let i = 0; i < 35; i++) {
  const mode = i % 5;
  if (mode === 0) {
    // Technical
    const ent = seenCodeEntities[i % seenCodeEntities.length];
    addRecord({
      text: `Analyze the flight dynamics telemetry recording from ${ent.name} to detect attitude control jitter.`,
      gold_class: ent.cls as GoldClass,
      sensitivity_level: ent.lvl,
      entity_category: ent.cat,
      terminology_group: `${ent.name.toLowerCase()}_scaled_seen`,
      seen_or_unseen: 'SEEN',
      template_family: 'programmatic_tech_dev',
      split: 'DEV',
      hard_negative_group: null,
    });
  } else if (mode === 1) {
    // Identifiers
    const host = choice(seenInfraHosts);
    addRecord({
      text: `Verify Prometheus node-exporter metrics and disk latency on ${host}.`,
      gold_class: 'internal identifiers',
      sensitivity_level: 'INTERNAL',
      entity_category: 'INTERNAL_IDENTIFIER',
      terminology_group: 'nova_infra_scaled_seen',
      seen_or_unseen: 'SEEN',
      template_family: 'programmatic_infra_dev',
      split: 'DEV',
      hard_negative_group: null,
    });
  } else if (mode === 2) {
    // Secrets
    const tokenHex = Array.from({ length: 32 }, () => Math.floor(rng() * 16).toString(16)).join('');
    addRecord({
      text: `Rotate the staging telemetry ingestion token nova_sec_test_${tokenHex} in the vault service.`,
      gold_class: 'secrets',
      sensitivity_level: 'RESTRICTED',
      entity_category: 'CREDENTIAL',
      terminology_group: 'credentials_scaled_seen',
      seen_or_unseen: 'SEEN',
      template_family: 'programmatic_secret_dev',
      split: 'DEV',
      hard_negative_group: null,
    });
  } else if (mode === 3) {
    // PII
    const badgeNum = Math.floor(10000 + rng() * 89999);
    addRecord({
      text: `Process dental insurance claim for employee badge NV-EMP-${badgeNum} with Delta Dental group policy #99281.`,
      gold_class: 'PII',
      sensitivity_level: 'CONFIDENTIAL',
      entity_category: 'PII',
      terminology_group: 'pii_scaled_seen',
      seen_or_unseen: 'SEEN',
      template_family: 'programmatic_pii_dev',
      split: 'DEV',
      hard_negative_group: null,
    });
  } else {
    // Benign
    const benignDev = [
      'How does the Linux virtual memory manager handle page faults for anonymous memory mappings?',
      'Explain the difference between shallow copy and deep copy in JavaScript object manipulation.',
      'What are the key trade-offs between gRPC and RESTful JSON APIs for low-latency backend services?',
      'How do I calculate the discrete Fourier transform of a finite sequence using the Cooley-Tukey algorithm?',
      'Draft a professional meeting agenda for an all-hands quarterly engineering architecture review.',
    ];
    addRecord({
      text: choice(benignDev),
      gold_class: 'benign',
      sensitivity_level: 'PUBLIC',
      entity_category: 'BENIGN',
      terminology_group: 'general_tech_scaled_seen',
      seen_or_unseen: 'SEEN',
      template_family: 'programmatic_benign_dev',
      split: 'DEV',
      hard_negative_group: null,
    });
  }
}

// Generate diverse TEST prompts (Held-out UNSEEN terminology & domains strictly) (70 prompts)
const unseenCodeEntities = [
  { name: 'Project Chimera', domain: 'directed energy beam optics', cat: 'CONFIDENTIAL_TECHNICAL', cls: 'confidential technical/financial information', lvl: 'RESTRICTED' as SensitivityLevel },
  { name: 'Project Hyperion', domain: 'satellite laser communications downlink', cat: 'CONFIDENTIAL_TECHNICAL', cls: 'confidential technical/financial information', lvl: 'CONFIDENTIAL' as SensitivityLevel },
  { name: 'Project Cerberus', domain: 'tactical zero-trust mesh routing', cat: 'CONFIDENTIAL_TECHNICAL', cls: 'confidential technical/financial information', lvl: 'CONFIDENTIAL' as SensitivityLevel },
  { name: 'Project Talon', domain: 'takeover acquisition model for AeroPrecision', cat: 'CONFIDENTIAL_FINANCIAL', cls: 'confidential technical/financial information', lvl: 'RESTRICTED' as SensitivityLevel },
  { name: 'Sentinel-6', domain: 'multi-spectral sensor fusion suite', cat: 'CONFIDENTIAL_TECHNICAL', cls: 'confidential technical/financial information', lvl: 'CONFIDENTIAL' as SensitivityLevel },
];

const unseenInfraHosts = [
  'grid-quantum.internal.novasystems.net',
  'secure-broker.prod.novasystems.net',
  'edge-node-09.tactical.novasystems.net',
  'chimera-optics.lab.novasystems.net',
  'hyperion-downlink.station.novasystems.net',
];

const unseenRepos = [
  'novasys-optics/laser-downlink',
  'novasys-payload/strike-core',
  'novasys-edge/cerberus-mesh',
  'novasys-sensor/sentinel-fusion',
  'novasys-corp/talon-acquisition',
];

const unseenJiraPrefixes = ['NOVA-PAYLOAD', 'NOVA-OPTICS', 'NOVA-DIR', 'NOVA-TACTICAL', 'NOVA-MERGER'];

for (let i = 0; i < 70; i++) {
  const mode = i % 5;
  if (mode === 0) {
    // Unseen Technical / Strategic
    const ent = unseenCodeEntities[i % unseenCodeEntities.length];
    const actions = [
      'Synthesize the flight envelope safety limits for',
      'Calculate the power consumption profile for',
      'Optimize the real-time sensor processing pipeline in',
      'Draft confidential technical risk assessment for',
      'Review the export-controlled ITAR telemetry data for',
    ];
    const act = actions[Math.floor(rng() * actions.length)];
    addRecord({
      text: `${act} ${ent.name} during autonomous test range operations.`,
      gold_class: ent.cls as GoldClass,
      sensitivity_level: ent.lvl,
      entity_category: ent.cat,
      terminology_group: `${ent.name.toLowerCase().replace(/[^a-z0-9]/g, '_')}_unseen`,
      seen_or_unseen: 'UNSEEN',
      template_family: 'programmatic_tech_test',
      split: 'TEST',
      hard_negative_group: null,
    });
  } else if (mode === 1) {
    // Unseen Infrastructure & Repos
    const host = choice(unseenInfraHosts);
    const repo = choice(unseenRepos);
    addRecord({
      text: `Sync production container deployment on ${host} from main branch of repository ${repo}.`,
      gold_class: 'internal identifiers',
      sensitivity_level: 'INTERNAL',
      entity_category: 'INTERNAL_IDENTIFIER',
      terminology_group: 'nova_infra_scaled_unseen',
      seen_or_unseen: 'UNSEEN',
      template_family: 'programmatic_infra_test',
      split: 'TEST',
      hard_negative_group: null,
    });
  } else if (mode === 2) {
    // Unseen Jira
    const pfx = choice(unseenJiraPrefixes);
    const num = 1000 + Math.floor(rng() * 8999);
    const issueKey = `${pfx}-${num}`;
    const unseenTopics = [
      'optical beam jitter under atmospheric thermal blooming',
      'laser diode array current transient overshoots',
      'zero-trust tactical certificate revocation propagation delays',
      'confidential valuation discrepancy in patent portfolio appraisal',
      'infrared focal plane array cryogenic cooler power draw',
    ];
    addRecord({
      text: `Review the confidential attachments and root cause analysis in Jira issue ${issueKey} regarding ${choice(unseenTopics)}.`,
      gold_class: 'internal identifiers',
      sensitivity_level: 'INTERNAL',
      entity_category: 'INTERNAL_IDENTIFIER',
      terminology_group: 'nova_jira_scaled_unseen',
      seen_or_unseen: 'UNSEEN',
      template_family: 'programmatic_jira_test',
      split: 'TEST',
      hard_negative_group: null,
    });
  } else if (mode === 3) {
    // Unseen Secrets
    const tokenHex = Array.from({ length: 40 }, () => Math.floor(rng() * 16).toString(16)).join('');
    const formats = [
      `Export tactical API authorization key nova_sec_unseen_prod_${tokenHex} to the secure telemetry daemon.`,
      `Authenticate to tactical edge database postgresql://tactical_operator:CerberusSecure2026!@${choice(unseenInfraHosts)}:5432/mission_db.`,
      `Verify secret signing key sk-unseen-hyperion-${tokenHex.slice(0, 24)} before issuing telemetry commands.`,
    ];
    addRecord({
      text: choice(formats),
      gold_class: 'secrets',
      sensitivity_level: 'RESTRICTED',
      entity_category: 'CREDENTIAL',
      terminology_group: 'credentials_scaled_unseen',
      seen_or_unseen: 'UNSEEN',
      template_family: 'programmatic_secret_test',
      split: 'TEST',
      hard_negative_group: null,
    });
  } else {
    // Unseen Benign (General Science, Literature, Engineering)
    const unseenBenign = [
      'Explain the working principle of a Stirling engine and its theoretical Carnot efficiency comparison.',
      'How does CRISPR-Cas9 achieve targeted double-strand DNA cleavage in molecular biology research?',
      'What are the aerodynamic benefits of raked wingtips compared to conventional blended winglets on commercial airliners?',
      'Summarize the core themes and character arcs in Dostoyevskys novel The Brothers Karamazov.',
      'How does the fast Fourier transform algorithm achieve O(N log N) computational complexity over naive O(N^2) evaluation?',
      'What are the physiological effects of high altitude hypobaric hypoxia on human arterial oxygen saturation?',
      'Explain the concept of quantum entanglement and the violation of Bell inequalities in physics experiments.',
      'How do I calculate the shear stress distribution in an I-beam under transverse mechanical loading?',
      'What are the key differences between synchronous and induction electric motors used in aerospace actuation?',
      'Draft a polite request to the IT helpdesk for a replacement monitor display cable for workstation 4B.',
    ];
    addRecord({
      text: choice(unseenBenign),
      gold_class: 'benign',
      sensitivity_level: 'PUBLIC',
      entity_category: 'BENIGN',
      terminology_group: 'general_tech_scaled_unseen',
      seen_or_unseen: 'UNSEEN',
      template_family: 'programmatic_benign_test',
      split: 'TEST',
      hard_negative_group: null,
    });
  }
}

// =========================================================================
// 10. VALIDATION & STATISTICAL AUDIT
// Ensure zero leakage, strict splits, and valid schema
// =========================================================================

console.log(`Generated total records: ${records.length}`);

// Leakage prevention verification
const trainDevUnseen = records.filter(r => (r.split === 'TRAIN' || r.split === 'DEV') && r.seen_or_unseen === 'UNSEEN');
if (trainDevUnseen.length > 0) {
  throw new Error(`LEAKAGE DETECTED: Found ${trainDevUnseen.length} UNSEEN records in TRAIN/DEV splits!`);
}

// Check paraphrase family isolation
const familySplits = new Map<string, Set<string>>();
for (const r of records) {
  if (r.template_family.startsWith('PARA-')) {
    if (!familySplits.has(r.template_family)) {
      familySplits.set(r.template_family, new Set());
    }
    familySplits.get(r.template_family)!.add(r.split);
  }
}

for (const [fam, splits] of familySplits.entries()) {
  if (splits.size > 1) {
    throw new Error(`LEAKAGE DETECTED: Paraphrase family ${fam} spans multiple splits: ${Array.from(splits).join(', ')}`);
  }
}

// Check hard negative pairs
const hnGroups = new Map<string, NovaDatasetRecord[]>();
for (const r of records) {
  if (r.hard_negative_group) {
    if (!hnGroups.has(r.hard_negative_group)) {
      hnGroups.set(r.hard_negative_group, []);
    }
    hnGroups.get(r.hard_negative_group)!.push(r);
  }
}

for (const [grp, recs] of hnGroups.entries()) {
  if (recs.length < 2) {
    throw new Error(`INCOMPLETE HARD NEGATIVE: Group ${grp} has only ${recs.length} record(s).`);
  }
  const hasBenign = recs.some(r => r.gold_class === 'benign');
  const hasSensitive = recs.some(r => r.gold_class !== 'benign');
  if (!hasBenign || !hasSensitive) {
    throw new Error(`INVALID HARD NEGATIVE: Group ${grp} lacks both benign and sensitive counterparts.`);
  }
}

// Class counts
const classCounts: Record<GoldClass, number> = {
  'PII': 0,
  'secrets': 0,
  'internal identifiers': 0,
  'confidential technical/financial information': 0,
  'benign': 0,
};

const splitCounts = { TRAIN: 0, DEV: 0, TEST: 0 };
const seenCounts = { SEEN: 0, UNSEEN: 0 };
let hardNegativeCount = 0;

for (const r of records) {
  classCounts[r.gold_class]++;
  splitCounts[r.split]++;
  seenCounts[r.seen_or_unseen]++;
  if (r.hard_negative_group) hardNegativeCount++;
}

const summary = {
  organization: 'NOVA Systems',
  total_examples: records.length,
  splits: splitCounts,
  classes: classCounts,
  seen_unseen: seenCounts,
  hard_negatives: {
    total_hard_negative_examples: hardNegativeCount,
    distinct_pairs: hnGroups.size,
  },
  annotation_status: 'PENDING HUMAN VALIDATION',
  deterministic_seed: 42,
  leakage_prevention: {
    unseen_in_train_or_dev: 0,
    paraphrase_families_split_isolation: 'STRICTLY ENFORCED (Zero leakage)',
  },
};

console.log('Dataset Summary:');
console.log(JSON.stringify(summary, null, 2));

// =========================================================================
// 11. EXPORT DATASET ARTIFACTS
// =========================================================================

const outDir = path.resolve('datasets/nova_systems');
if (!fs.existsSync(outDir)) {
  fs.mkdirSync(outDir, { recursive: true });
}

// JSON array format
const jsonPath = path.join(outDir, 'nova_research_dataset.json');
fs.writeFileSync(jsonPath, JSON.stringify(records, null, 2), 'utf-8');
console.log(`Saved JSON: ${jsonPath}`);

// JSONL format
const jsonlPath = path.join(outDir, 'nova_research_dataset.jsonl');
const jsonlLines = records.map(r => JSON.stringify(r)).join('\n');
fs.writeFileSync(jsonlPath, jsonlLines, 'utf-8');
console.log(`Saved JSONL: ${jsonlPath}`);

// Summary JSON
const summaryPath = path.join(outDir, 'dataset_summary.json');
fs.writeFileSync(summaryPath, JSON.stringify(summary, null, 2), 'utf-8');
console.log(`Saved Summary: ${summaryPath}`);
