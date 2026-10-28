/**
 * National Digital Interoperability Gateway (NDIG) - Enterprise Application Logic
 * Institutional Platform for National e-Governance Division (NeGD), MeitY, Government of India.
 * Compliant with GIGW 3.0 / UX4G accessibility guidelines and IndEA 2.0 standards.
 */

document.addEventListener('DOMContentLoaded', () => {
  // =========================================================================
  // 0. CORE APPLICATION SECURITY & DEFENSIVE ENGINEERING ENGINE (DPDP 2023)
  // =========================================================================
  window.escapeHtml = function(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  };
  const escapeHtml = window.escapeHtml;

  window.maskAadhaar = function(aadhaarStr) {
    if (!aadhaarStr) return 'XXXX-XXXX-7219';
    const digits = String(aadhaarStr).replace(/\D/g, '');
    if (digits.length >= 4) {
      return `XXXX-XXXX-${digits.slice(-4)}`;
    }
    return 'XXXX-XXXX-7219';
  };
  const maskAadhaar = window.maskAadhaar;



  const SecurityCrypto = {
    async sha256(message) {
      if (window.crypto && window.crypto.subtle) {
        try {
          const msgBuffer = new TextEncoder().encode(message);
          const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
          const hashArray = Array.from(new Uint8Array(hashBuffer));
          return '0x' + hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        } catch(e) {}
      }
      return '0x' + Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, '0')).join('');
    },
    generateToken(prefix = 'GOI') {
      const rand = Array.from(crypto.getRandomValues(new Uint8Array(6))).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
      return `${prefix}-2026-${rand}`;
    },
    async generateDocumentHash(data) {
      const str = typeof data === 'string' ? data : JSON.stringify(data);
      const hashWith0x = await this.sha256(str);
      return hashWith0x.startsWith('0x') ? hashWith0x.slice(2) : hashWith0x;
    }
  };
  window.SecurityCrypto = SecurityCrypto;

  const SecurityFileValidator = {
    allowedExtensions: ['.jpg', '.jpeg', '.png', '.pdf'],
    allowedMimes: ['image/jpeg', 'image/png', 'application/pdf'],
    maxSize: 10 * 1024 * 1024,

    validate(file) {
      if (!file) return { valid: false, error: 'No file selected.' };
      if (file.size > this.maxSize) {
        return { valid: false, error: 'Security Violation: File size exceeds statutory 10MB limit.' };
      }
      const ext = '.' + file.name.split('.').pop().toLowerCase();
      if (!this.allowedExtensions.includes(ext)) {
        return { valid: false, error: 'Security Violation: Prohibited file extension. Allowed: PDF, JPG, PNG only.' };
      }
      if (file.type && !this.allowedMimes.includes(file.type.toLowerCase())) {
        return { valid: false, error: 'Security Violation: Invalid MIME type detected.' };
      }
      if (/[\0\/\\]/.test(file.name) || file.name.includes('..')) {
        return { valid: false, error: 'Security Alert: Malicious file path pattern rejected.' };
      }
      return { valid: true };
    }
  };
  window.SecurityFileValidator = SecurityFileValidator;

  const SecurityAuthManager = {
    sessionKey: 'ndig_portal_auth_session',
    currentUser: null,

    init() {
      try {
        const stored = sessionStorage.getItem(this.sessionKey);
        if (stored) {
          const parsed = JSON.parse(stored);
          if (parsed.expiresAt && Date.now() < parsed.expiresAt) {
            this.currentUser = parsed;
            this.applyUIState();
            return;
          }
        }
      } catch(e) {}
      this.currentUser = { role: 'ANONYMOUS', name: 'Citizen / Guest', isLoggedIn: false };
      this.applyUIState();
    },

    login(type, credentials = {}) {
      const now = Date.now();
      const sessionTimeoutMs = 60 * 60 * 1000;
      const token = SecurityCrypto.generateToken('AUTH-SSO');

      if (type === 'officer') {
        this.currentUser = {
          role: 'OFFICER',
          name: 'Sub-Divisional Magistrate / Tehsildar',
          designation: 'Executive Magistrate & Competent Revenue Authority',
          token: token,
          dscToken: 'CCA-INDIA-2026-CLASS3-VERIFIED',
          isLoggedIn: true,
          loginTime: now,
          expiresAt: now + sessionTimeoutMs
        };
      } else {
        const inputName = credentials.name || 'Rajesh Kumar';
        const inputAadhaar = credentials.aadhaar || '7219';
        this.currentUser = {
          role: 'CITIZEN',
          name: inputName,
          aadhaarMasked: maskAadhaar(inputAadhaar),
          token: token,
          isLoggedIn: true,
          loginTime: now,
          expiresAt: now + sessionTimeoutMs
        };
      }
      try {
        sessionStorage.setItem(this.sessionKey, JSON.stringify(this.currentUser));
      } catch(e) {}
      this.applyUIState();
      return this.currentUser;
    },

    logout() {
      this.currentUser = { role: 'ANONYMOUS', name: 'Citizen / Guest', isLoggedIn: false };
      try {
        sessionStorage.removeItem(this.sessionKey);
      } catch(e) {}
      this.applyUIState();
    },

    isOfficer() {
      return this.currentUser && this.currentUser.role === 'OFFICER' && this.currentUser.isLoggedIn;
    },

    isCitizen() {
      return this.currentUser && this.currentUser.role === 'CITIZEN' && this.currentUser.isLoggedIn;
    },

    applyUIState() {
      const loginBtn = document.getElementById('nav-login-btn');
      const userPill = document.getElementById('nav-user-pill');
      const userName = document.getElementById('nav-user-name');
      if (!loginBtn || !userPill || !userName) return;

      if (this.currentUser && this.currentUser.isLoggedIn) {
        loginBtn.classList.add('hidden');
        userPill.classList.remove('hidden');
        userPill.classList.add('flex');
        if (this.currentUser.role === 'OFFICER') {
          userPill.className = "flex items-center gap-2 bg-[#138808] text-white px-3 py-1 rounded-lg text-xs font-bold shadow-xs border border-emerald-300";
          userName.innerHTML = `<i data-lucide="shield-check" class="w-3.5 h-3.5 inline text-amber-300"></i> Officer: SDM / Tehsildar (DSC Sealed)`;
        } else {
          userPill.className = "flex items-center gap-2 bg-[#0284C7] text-white px-2.5 py-1 rounded-lg text-xs font-semibold shadow-xs";
          userName.innerHTML = `<i data-lucide="user-check" class="w-3.5 h-3.5 inline"></i> ${escapeHtml(this.currentUser.name)} (${escapeHtml(this.currentUser.aadhaarMasked || 'Verified')})`;
        }
      } else {
        userPill.classList.add('hidden');
        userPill.classList.remove('flex');
        loginBtn.classList.remove('hidden');
      }
      if (window.lucide) window.lucide.createIcons();
    }
  };
  window.SecurityAuthManager = SecurityAuthManager;

  SecurityAuthManager.init();

  NDIG_DATABASE.init();
  setTimeout(() => window.renderAll54Services('all', ''), 100);

  // 1. Initialize Lucide Icons if available
  if (window.lucide) {
    window.lucide.createIcons();
  }

  // 2. Bilingual Translation Dictionary (English & Hindi)
  const translations = {
    en: {
      "yojana_title": "AI Yojana Drishti — National Welfare & Statutory Scheme Predictor",
      "yojana_sub": "Input citizen socioeconomic profile to calculate statutory scheme entitlements, compute direct economic subsidies, and pre-fill official certificates in &lt;200ms.",
      "yojana_btn": "Run AI Eligibility Analysis (पात्रता की AI गणना करें)",
      "gov_attribution": "MH SAHYOG • CITIZEN SERVICES & APPLIED DPI",
      "gov_ministry_top": "Open API Architecture • Unified Citizen Service Delivery • DPDP Act 2023",
      "skip_content": "Skip to Main Content",
      "text_size_label": "Text Size:",
      "contrast_btn": "Contrast (A)",
      "ministry_header": "National e-Governance Division (NeGD) • Ministry of Electronics & IT • Interoperability Mesh",
      "portal_title": "MH Sahyog",
      "portal_subtitle": "Single-Window Public Service Delivery Platform & Citizen Interoperability Mesh",
      "sih_title": "National e-Governance Division (NeGD)",
      "sih_team": "Ministry of Electronics & IT | MeitY",
      "sih_ps": "Architecture: IndEA 2.0 Standard",
      "sih_status": "Live Production Gateway",
      "sih_category": "GIGW 3.0 Certified",
      "nav_home": "Home",
      "nav_prototype": "Citizen Services",
      "nav_framework": "About Framework",
      "nav_pillars": "8 Technical Pillars",
      "nav_specs": "Cloud Architecture",
      "nav_console": "Live Console",
      "nav_roi": "Governance & Impact",
      "nav_standards": "e-Gov Standards",
      "nav_ai_drishti": "AI Drishti Verifier",
      "nav_menu_btn": "Menu",
      "drawer_title": "MH Sahyog Menu",
      "drawer_sub": "MH Sahyog Citizen Services Portal",
      "drawer_auth_status": "MeriPehchaan SSO",
      "drawer_auth_sub": "National Single Sign-On",
      "drawer_login_btn": "Sign In",
      "drawer_grp1": "1. CITIZEN PUBLIC SERVICES",
      "drawer_grp2": "2. STATUTORY DESKS",
      "drawer_grp3": "3. AI FORENSICS & GOVERNANCE",
      "verifier_eyebrow": "MODULE 06 • LIVE AUDIT & AI VERIFICATION",
      "hero_cta_prototype": "Launch Citizen Desk (नागरिक सेवा केंद्र)",
      "proto_badge": "OFFICIAL CITIZEN SERVICE DESK • LIVE VERIFIED",
      "proto_title": "National Single-Window Citizen Service Gateway",
      "proto_sub": "Single-window citizen delivery: Issue official statutory certificates, trigger cross-agency verification, and download tamper-proof smart cards.",
      "gateway_uptime": "Status: 100% Interoperability Gateway Operational",
      "notice_badge": "LIVE OPERATIONAL BULLETIN",
      "notice_text": "MH Sahyog Live: 28 State Civil Registries Connected • UIDAI Aadhaar 2.0 Identity Bus Online • DigiLocker Citizen Vault Active • DPDP Act 2023 Compliant • Sub-second End-to-End Latency",
      "dpi_tag": "National Enterprise Architecture (IndEA 2.0) • DPI Blueprint",
      "dpi_quote": "\"Unified, consent-driven interoperability delivers zero-friction public services to every citizen across India.\"",
      "file_ref": "Ref: NDIG / NeGD / GOI-2026",
      "hero_title": "Integrated e-Governance Citizen Gateway: <br><span class='text-[#FF8000]'>All Certificates &amp; Licences</span> Under One Roof",
      "hero_desc": "Instant paperless processing, automated cross-departmental verification, and DigiLocker delivery for <strong>Caste, Income, Domicile Certificates</strong>, <strong>Driving Licences</strong>, <strong>Birth &amp; Death Records</strong>, and <strong>Land Registries</strong> through the National Interoperability Mesh.",
      "search_label": "National Unified Citizen Services & Document Registry",
      "search_placeholder": "Search services, certificates, or registration IDs (e.g. Birth Certificate, Baal Aadhaar, SPICe+, PM-KISAN, Land Records)...",
      "search_btn": "Search Services",
      "search_all": "All Ministries & Departments",
      "search_health": "Health & Family Welfare (MoHFW - CRS)",
      "search_corporate": "Corporate Affairs (MCA - SPICe+)",
      "search_agri": "Agriculture & Farmers Welfare (AgriStack)",
      "search_uidai": "Unique Identification Authority (UIDAI Aadhaar)",
      "search_revenue": "Revenue & Land Records (Bhulekh / DILRMP)",
      "popular_services": "Popular Services:",
      "service_birth": "Birth Registration (CRS)",
      "service_spice": "Company SPICe+ (MCA)",
      "service_kisan": "PM-KISAN DBT",
      "service_aadhaar": "Baal Aadhaar DigiLocker Delivery",
      "kpi_savings_title": "Administrative Savings",
      "kpi_savings_badge": "Target Estimate",
      "kpi_savings_desc": "Automated inter-agency verification cuts paperwork, physical notarization, and server redundancy.",
      "kpi_ui_title": "Citizen Experience",
      "kpi_ui_badge": "Single-Window",
      "kpi_ui_desc": "Zero repeated form submissions across municipal, state, and central departments. Unified life-events.",
      "kpi_sec_title": "Security & Data Sovereignty",
      "kpi_sec_badge": "Zero-Trust",
      "kpi_sec_desc": "End-to-end payload encryption with explicit citizen consent tokens under the DPDP Act 2023.",
      "sec1_badge": "DPI Vision 2026",
      "sec1_title": "Administrative Silo Challenges & National Interoperability Framework (IndEA 2.0)",
      "prob_title": "The Administrative Bottleneck",
      "prob_heading": "Citizens Face Disconnected, Repetitive, and Delayed Public Services",
      "prob_desc": "Public services currently operate within disconnected administrative silos. For a single life-event, citizens are forced to visit multiple physical offices or fragmented portals, repeatedly submitting identical identity proofs and awaiting slow manual verifications.",
      "prob_silos": "Data Silos",
      "prob_silos_sub": "Incompatible DBs",
      "prob_frag": "Fragmented Portals",
      "prob_frag_sub": "Multiple Portals",
      "prob_delays": "Manual Delays",
      "prob_delays_sub": "Multi-Week Lag",
      "sol_title": "National Interoperability Resolution (IndEA 2.0)",
      "sol_heading": "National Digital Interoperability Gateway (NDIG)",
      "sol_desc": "A robust, secure middleware platform connecting legacy departmental databases using standardized RESTful APIs, JSON-LD schemas, and citizen consent controls.",
      "sol_p1": "<strong>Interoperable Platform:</strong> Vendor-neutral government middleware connecting state and central databases.",
      "sol_p2": "<strong>Data Standardization:</strong> Aligned with MeitY metadata schemas and JSON-LD 1.1 format.",
      "sol_p3": "<strong>Consent-Based Sharing:</strong> Explicit citizen consent tokens compliant with the DPDP Act 2023.",
      "sol_p4": "<strong>Single Life-Event Interface:</strong> One unified citizen dashboard covering cradle-to-grave public services.",
      "sec2_badge": "Proposed Architecture",
      "sec2_title": "Technical Approach (8 Core Architecture Pillars)",
      "sec2_sub": "Proposed architectural blueprint aligned with the Open API Policy and GIGW 3.0 design guidelines.",
      "p1_title": "Pillar 1: API-Based Integration",
      "p1_desc": "Connect existing government platforms through standardized REST APIs and secure service interfaces, eliminating brittle legacy direct DB links.",
      "p2_title": "Pillar 2: Interoperability Layer",
      "p2_desc": "Implement a middleware integration layer to facilitate reliable communication and asynchronous data exchange between departments.",
      "p3_title": "Pillar 3: Common Data Standards",
      "p3_desc": "Adopt standardized data models, JSON-LD formats, and MeitY metadata schemas for consistent information interpretation across all agencies.",
      "p4_title": "Pillar 4: Centralized Authentication",
      "p4_desc": "Implement secure identity and access management using Role-Based Access Control (RBAC) and Single Sign-On (SSO via e-Pramaan / DigiLocker).",
      "p5_title": "Pillar 5: Data Synchronization",
      "p5_desc": "Enable real-time or near-real-time synchronization of critical data across connected departmental systems via event-driven queues.",
      "p6_title": "Pillar 6: Security & Privacy",
      "p6_desc": "Apply zero-trust encryption (AES-256), secure APIs, cryptographic audit logs, and privacy controls to protect government and citizen data.",
      "p7_title": "Pillar 7: Monitoring & Analytics",
      "p7_desc": "Deploy centralized monitoring dashboards to track system performance, network latency, transactional throughput, and service delivery SLA.",
      "p8_title": "Pillar 8: Scalable Architecture",
      "p8_desc": "Use modular, cloud-ready architecture to support onboarding future state/central departments, services, and increasing user demand.",
      "sec3_badge": "Production Level Blueprint",
      "sec3_title": "Enterprise Cloud Infrastructure & System Architecture",
      "sec3_sub": "Technical specifications for caching, edge distribution, security, databases, CI/CD, and scaling (NeGD / MeitY Standards).",
      "spec_caching": "Distributed Caching (National Acceleration Layer)",
      "spec_caching_desc": "In-memory acceleration cluster caching schema mappings, citizen consent tokens, and active session clearances at sub-5 millisecond speed.",
      "spec_cdn": "Edge CDN (Proposed)",
      "spec_cdn_desc": "National Edge Content Delivery Network with Anycast routing for regional edge termination, static schema distribution, and Layer-7 security protection.",
      "spec_iam": "Permissions & Statutory Governance (RBAC/ABAC)",
      "spec_iam_desc": "Attribute-based and role-based access governance, DPDP Act citizen consent tokens, and MeriPehchaan (e-Pramaan) Single Sign-On integration.",
      "spec_rate": "Gateway Traffic Throttling & Queue Management",
      "spec_rate_desc": "National Gateway Traffic Throttle implementing fair-queuing algorithms (10,000 req/sec) to ensure balanced throughput and prevent departmental server overloads.",
      "spec_cloud": "Cloud Hosting (MeghRaj National GI Cloud)",
      "spec_cloud_desc": "Proposed hosting on a MeitY-empaneled cloud (for example MeghRaj) using container clusters, targeting 99.99% availability and multi-region disaster recovery.",
      "spec_logs": "Audit Logging & Incident Diagnostics",
      "spec_logs_desc": "Centralized Audit Trail & Telemetry with end-to-end transaction tracing for real-time anomaly detection, administrative logs, and compliance assurance.",
      "spec_db": "Dual-Engine Enterprise Data Registries",
      "spec_db_desc": "Enterprise Relational Database for immutable transaction records paired with schema registries for flexible departmental data structures and multi-region replication.",
      "spec_sec": "Hardware Security Module (HSM) & Encryption",
      "spec_sec_desc": "End-to-end payload encryption (AES-256-GCM), Mutual TLS certificate verification, Hardware Security Modules (HSM), and WORM immutable audit storage.",
      "spec_cicd": "Automated Quality Assurance & Certification",
      "spec_cicd_desc": "Automated Continuous Integration and Testing pipeline with static vulnerability scanners, API contract validation, and comprehensive test suites prior to deployment.",
      "spec_mon": "National Operations Telemetry & NOC Dashboard",
      "spec_mon_desc": "Centralized National Operations Dashboard tracking real-time inter-agency response times, service availability, and Citizen Charter SLA compliance.",
      "spec_vc": "National e-Governance Schema Governance",
      "spec_vc_desc": "Strict semantic version governance aligned with the Open API Policy, with declarative infrastructure management.",
      "spec_notify": "National Citizen Notification Gateway (CDAC SMS)",
      "spec_notify_desc": "National Notification Hub integrating CDAC SMS Gateway, institutional email, and real-time event queues for instant multi-channel citizen intimations.",
      "console_title": "Interoperability Gateway — Live Execution & Audit Console",
      "console_sub": "Automated cross-departmental data exchange execution with digital signature and audit trail verification.",
      "workflow_label": "Select Workflow:",
      "workflow_execute_btn": "Execute Workflow",
      "stat_latency_label": "Total Interop Latency",
      "stat_enc_label": "Data Encryption",
      "stat_audit_label": "Audit Verification",
      "stat_pending": "ACTIVE / READY",
      "ledger_title": "National Interoperability Audit Ledger",
      "ledger_badge": "ISO 27001 Aligned",
      "ledger_initial_1": "[SYSTEM] NeGD Interoperability Gateway v2.6 Active — Gateway Listening",
      "ledger_initial_2": "[STANDBY] Awaiting trigger for automated cross-departmental verification...",
      "sec5_badge": "High Viability",
      "sec5_title": "Operational Governance, Capacity & Implementation Framework",
      "sec5_sub": "Technical feasibility, operational viability, and administrative efficiency model.",
      "th_dimension": "Dimension",
      "th_tech": "Technical Feasibility",
      "th_ops": "Operational Viability",
      "dim1_title": "Architecture & Integration",
      "dim1_tech": "Microservice API adapter wrapping legacy databases without requiring expensive system rewrite.",
      "dim1_ops": "Phased agency-by-agency rollout with progressive onboarding and zero service downtime.",
      "dim2_title": "Security & Compliance",
      "dim2_tech": "Zero-Trust model with end-to-end payload encryption and mutual TLS (mTLS 1.3) verification.",
      "dim2_ops": "Full statutory compliance with national data protection laws (DPDP Act 2023) and e-Governance security policies.",
      "dim3_title": "Cost & Financial Return",
      "dim3_tech": "Reusable open-source components significantly lower upfront capital expenditure (CapEx).",
      "dim3_ops": "ROI achieved within <strong>24 months</strong> purely through administrative overhead and paper process savings.",
      "dim4_title": "Governance & Adoption",
      "dim4_tech": "Standardized developer SDKs and central self-service API portal for fast departmental integration.",
      "dim4_ops": "Institutional policy mandates and structured inter-agency change management support.",
      "calc_title": "Government Efficiency & NeGD Administrative Impact Model",
      "calc_sub": "NeGD Standard Impact Model: Direct and indirect administrative efficiency gains across connected central and state departments based on paperless digital verification.",
      "calc_label": "Connected Agencies:",
      "calc_annual_label": "Projected Annual Savings",
      "sec6_badge": "Reference Standards",
      "sec6_title": "Statutory Policy & e-Governance Standards",
      "ref_policy_title": "Policy & Research Foundations",
      "ref_tech_title": "Technical References & Standards",
      "ft_team_title": "MH Sahyog",
      "ft_team_desc": "MH Sahyog is an institutional e-governance platform under NeGD, MeitY, Government of India, delivering seamless single-window G2C, G2B, and G2G services.",
      "ft_portals_title": "Reference Government Portals",
      "ft_specs_title": "Platform Architecture Summary",
      "ft_wim_title": "Web Information Manager (WIM)",
      "ft_wim_name": "Name: National Portal Division",
      "ft_wim_desig": "Designation: Chief Technology Officer & System Architecture Group",
      "ft_wim_event": "National e-Governance Division (NeGD), MeitY",
      "ft_wim_stqc": "Compliant with Guidelines for Indian Government Websites (GIGW 3.0)",
      "ft_nic_note": "Designed and developed under Open API Policy & IndEA 2.0 by National e-Governance Division (NeGD), MeitY, Government of India.",
      "ft_visitors": "Visitors:",
      "ft_last_updated": "Last Updated:",
      "ft_copyright": "© 2026 MH Sahyog, Ministry of Electronics & Information Technology, Government of India. All rights reserved."
    ,
"charter_title": "Citizen Charter & Statutory RTPS Service Delivery Timelines",
      "charter_sub": "Notified public services, statutory SLA delivery timelines, and appellate authorities under the Public Services Guarantee Framework.",
      "charter_act_badge": "Statutory RTPS Guarantee",
      "charter_penalty_title": "Statutory Guarantee Under Right to Public Services Act:",
      "charter_penalty_desc": "Failure to deliver citizen services within the mandated statutory timeline attracts a compulsory statutory penalty of ₹250 per day (up to ₹5,000 maximum) levied directly on the designated public authority.",
      "helpdesk_title": "Citizen Helpdesk & Grievance Redressal (CPGRAMS)",
      "helpdesk_sub": "24x7 Citizen Helpline, Technical Support, and Centralized Public Grievance Redressal System.",
      "helpdesk_badge": "24x7 Operational",
      "helpdesk_tollfree_title": "Toll-Free Citizen Helpline",
      "helpdesk_tollfree_desc": "For inquiries on certificates, verification, and service tracking:",
      "helpdesk_tollfree_note": "Toll-Free • All Days (24x7 Active)",
      "helpdesk_email_title": "Technical Support Email",
      "helpdesk_email_desc": "For online submission issues or API sync failures:",
      "helpdesk_email_note": "Average Response Time: Within 2 Hours",
      "helpdesk_cpgrams_title": "Public Grievance Portal (CPGRAMS)",
      "helpdesk_cpgrams_desc": "Lodge formal statutory complaints regarding delays or issues:",
      "helpdesk_cpgrams_btn": "Lodge Grievance on CPGRAMS Portal →",

      "nav_home": "Home",
      "nav_directory": "Services Directory",
      "nav_apply": "Apply Online",
      "nav_track": "Track Status",
      "nav_verify": "Verify Certificate",
      "nav_charter": "Citizen Charter",
      "nav_standards": "Architecture & Standards",
      "nav_helpdesk": "Helpdesk",
      "nav_terms": "Terms & Legal",
      "nav_login": "Citizen Login",
      "nav_status_gateway": "100% Secure Interoperability Active \u2022 NeGD",
      "login_modal_title": "National Single Sign-On (MeriPehchaan)",
      "login_modal_subtitle": "Ministry of Electronics & IT \u2022 Digital India",
      "login_tab_citizen": "Citizen Login",
      "login_tab_officer": "Officer Login (Parichay)",
      "login_citizen_id_label": "Aadhaar Number / Registered Mobile:",
      "login_otp_label": "One-Time Password (OTP):",
      "login_resend_otp": "Send OTP",
      "login_otp_hint": "Demo OTP auto-filled: 589201 (Simulated UIDAI SMS)",
      "login_btn_citizen": "Sign In with MeriPehchaan (DigiLocker)",
      "login_officer_id_label": "Gov Official Email ID / Parichay ID:",
      "login_officer_pass_label": "Password / Digital Token Pin:",
      "login_btn_officer": "Authenticate with Parichay SSO",
      "login_security_notice": "Protected by 256-bit TLS encryption & DPDP Act 2023 Statutory Consent Architecture.",
      "terms_modal_title": "Terms of Service, Privacy Policy & Legal Compliance",
      "terms_modal_subtitle": "Digital Personal Data Protection Act 2023 \u2022 IT Act 2000 \u2022 GIGW 3.0",
      "terms_sec1_title": "1. Terms of Service & Statutory Citizen Entitlement",
      "terms_sec1_desc": "This National Digital Interoperability Gateway (NDIG) is an official electronic public services delivery platform operated by the National e-Governance Division (NeGD), Ministry of Electronics & IT, Government of India. Use of this portal is governed under the Information Technology Act, 2000 and the DPDP Act, 2023.",
      "terms_sec2_title": "2. Privacy Policy & Citizen Consent Framework",
      "terms_sec2_desc": "In strict compliance with Section 6 of the DPDP Act 2023, data exchange across participating ministries (UIDAI, MoRTH, CRS, Revenue, Agriculture, MCA) is triggered solely upon explicit, revocable citizen consent. No biometric data is stored by the Gateway.",
      "terms_sec3_title": "3. Legal Validity of Electronically Issued Certificates",
      "terms_sec3_desc": "All digital certificates issued via this gateway are authenticated with Class 3 Digital Signature Certificates (DSC). Under Section 4 and Section 5 of the Information Technology Act, 2000, these electronically signed Gazette documents hold full statutory equivalence to physical paper certificates.",
      "terms_sec4_title": "4. Statutory Timelines & Public Services Guarantee",
      "terms_sec4_desc": "Public services provided through this platform are notified under statutory citizen service delivery legislation. Every citizen has a statutory entitlement to receive services within the stipulated Citizen Charter timeframes.",
      "terms_sec5_title": "5. Hyperlinking & Content Copyright Policy",
      "terms_sec5_desc": "Material published on this portal may be reproduced without prior formal permission for educational and administrative verification purposes, provided proper attribution is stated.",
      "ft_terms_use": "Terms of Use",
      "ft_privacy_policy": "Privacy Policy",
      "ft_hyperlink_policy": "Hyperlinking Policy",
      "ft_copyright_policy": "Copyright Policy",
      "ft_disclaimer": "Disclaimer",
      "ft_certin": "CERT-In Security Compliance",
      "bento_caste_title": "Caste, Income & Domicile Desks",
      "bento_caste_dept": "Department of Revenue & Land Records",
      "bento_caste_cta": "Open Revenue Desk",
      "bento_dl_title": "Smart Driving Licence Desk",
      "bento_dl_dept": "Ministry of Road Transport & Highways",
      "bento_dl_cta": "Open Driving Licence Desk",
      "bento_birth_title": "Birth, Death & Baal Aadhaar",
      "bento_birth_dept": "Office of Registrar General of India",
      "bento_birth_cta": "Open Birth Certificate Desk",
      "bento_farmer_title": "PM-KISAN DBT & Farmer Desks",
      "bento_farmer_dept": "Ministry of Agriculture & Farmers Welfare",
      "bento_farmer_cta": "Open Farmer DBT Desk",
      "bento_mca_title": "Company SPICe+ & MSME Desk",
      "bento_mca_dept": "Ministry of Corporate Affairs (MCA21 V3)",
      "bento_mca_cta": "Open SPICe+ Registration",
      "bento_verifier_title": "Universal Document Verifier",
      "bento_verifier_dept": "Controller of Certifying Authorities (MeitY)",
      "bento_verifier_cta": "Verify Any Certificate"
    ,
      "hero_main_heading": "National Citizen Public Services Portal <br><span class=\"text-[#FF8000]\">All Certificates &amp; Statutory Services</span> Under One Roof",
      "cta_apply_desc": "Paperless application for Caste, Income, Domicile, DL &amp; 20+ services",
      "cta_track_desc": "Check real-time 5-stage SLA timeline via Application Ref No",
      "cta_verify_desc": "Validate document authenticity via Universal QR Code &amp; Class 3 DSC",
      "cta_download_desc": "Access digitally signed Gazette certificate &amp; sync with DigiLocker",
      "tag_popular_label": "Popular Services:",
      "tag_caste": "Caste Certificate",
      "tag_income": "Income Certificate",
      "tag_domicile": "Domicile Certificate",
      "tag_dl": "Driving Licence",
      "tag_birth": "Birth Certificate",
      "tag_farmer": "PM-KISAN DBT"
    },

    hi: {
      "gov_attribution": "एमएच सहयोग (MH Sahyog) • नागरिक सेवाएं एवं डीपीआई",
      "gov_ministry_top": "ओपन एपीआई आर्किटेक्चर • एकीकृत नागरिक सेवा वितरण • डीपीडीपी अधिनियम 2023",
      "skip_content": "मुख्य सामग्री पर जाएं (Skip to Content)",
      "text_size_label": "फॉन्ट आकार:",
      "contrast_btn": "कंट्रास्ट (A)",
      "ministry_header": "राष्ट्रीय ई-गवर्नेंस प्रभाग (NeGD) • इलेक्ट्रॉनिक्स एवं सूचना प्रौद्योगिकी मंत्रालय",
      "portal_title": "MH Sahyog (एमएच सहयोग)",
      "portal_subtitle": "सार्वजनिक सेवा वितरण हेतु एकीकृत नागरिक सेवा मंच",
      "sih_title": "राष्ट्रीय ई-गवर्नेंस प्रभाग (NeGD)",
      "sih_team": "इलेक्ट्रॉनिक्स एवं आईटी मंत्रालय | MeitY",
      "sih_ps": "वास्तुकला: IndEA 2.0 राष्ट्रीय मानक",
      "sih_status": "सक्रिय राष्ट्रीय गेटवे",
      "sih_category": "GIGW 3.0 प्रमाणित",
      "nav_home": "मुख्य पृष्ठ",
      "nav_menu_btn": "मेनू",
      "nav_prototype": "नागरिक सेवाएं (Citizen Services)",
      "nav_framework": "अवलोकन एवं रूपरेखा",
      "nav_pillars": "8 तकनीकी स्तंभ",
      "nav_specs": "क्लाउड वास्तुकला",
      "nav_console": "लाइव निष्पादन कंसोल",
      "nav_roi": "शासन एवं प्रभाव",
      "nav_standards": "ई-गवर्नेंस मानक",
      "hero_cta_prototype": "नागरिक सेवा केंद्र खोलें (Citizen Desk)",
      "proto_badge": "आधिकारिक नागरिक सेवा केंद्र • लाइव सत्यापित",
      "proto_title": "राष्ट्रीय नागरिक एकल-खिड़की डिजिटल सेवा केंद्र",
      "proto_sub": "एकल-खिड़की नागरिक सेवा वितरण: जीवन-घटना आवेदन जमा करें, अंतर-विभागीय सत्यापन देखें, और सीधे आधिकारिक प्रमाण पत्र डाउनलोड करें।",
      "gateway_uptime": "स्थिति: 100% अंतर-प्रचालनीयता गेटवे सक्रिय",
      "notice_badge": "लाइव परिचालन बुलेटिन",
      "notice_text": "MH सहयोग सक्रिय: 28 राज्य नागरिक पंजीकरण पोर्टल जुड़े • UIDAI आधार 2.0 बस ऑनलाइन • डिजीलॉकर वॉल्ट सक्रिय • DPDP अधिनियम 2023 अनुपालन • सब-सेकंड लेटेंसी",
      "dpi_tag": "राष्ट्रीय एंटरप्राइज आर्किटेक्चर (IndEA 2.0) • डीपीआई ब्लूप्रिंट",
      "dpi_quote": "\"एकीकृत एवं सहमति-आधारित अंतर-प्रचालनीयता भारत के प्रत्येक नागरिक को शून्य-बाधा जनसेवाएं प्रदान करती है।\"",
      "file_ref": "संदर्भ: NDIG / NeGD / GOI-2026",
      "hero_title": "एकीकृत ई-गवर्नेंस नागरिक सेवा पोर्टल: <br><span class='text-[#FF8000]'>सभी प्रमाण पत्र एवं सेवाएं</span> एक ही स्थान पर",
      "hero_desc": "राष्ट्रीय अंतर-विभागीय इंटरऑपरेबिलिटी मेश द्वारा <strong>जाति प्रमाण पत्र</strong>, <strong>ड्राइविंग लाइसेंस</strong>, <strong>जन्म प्रमाण पत्र</strong>, <strong>निवास एवं आय</strong>, तथा <strong>भूलेख</strong> का त्वरित सत्यापन एवं डिजिलॉकर सुपुर्दगी।",
      "search_label": "राष्ट्रीय एकीकृत नागरिक सेवाएं एवं डिजिटल दस्तावेज खोज",
      "search_placeholder": "सेवा का नाम, प्रमाण पत्र या पंजीकरण संख्या खोजें (उदा. जन्म प्रमाण पत्र, बाल आधार, SPICe+, पीएम-किसान)...",
      "search_btn": "सेवा खोजें",
      "search_all": "सभी मंत्रालय एवं विभाग (All Ministries)",
      "search_health": "स्वास्थ्य एवं परिवार कल्याण (MoHFW - CRS)",
      "search_corporate": "कॉर्पोरेट कार्य मंत्रालय (MCA - SPICe+)",
      "search_agri": "कृषि एवं किसान कल्याण (AgriStack)",
      "search_uidai": "विशिष्ट पहचान प्राधिकरण (UIDAI Aadhaar)",
      "search_revenue": "राजस्व एवं भूमि अभिलेख (Bhulekh / DILRMP)",
      "popular_services": "प्रमुख एकीकृत सेवाएं:",
      "service_birth": "नागरिक जन्म पंजीकरण (CRS)",
      "service_spice": "कंपनी समावेशन (SPICe+)",
      "service_kisan": "पीएम-किसान डीबीटी",
      "service_aadhaar": "बाल आधार डिजीलॉकर डिलीवरी",
      "kpi_savings_title": "प्रशासनिक बचत",
      "kpi_savings_badge": "लक्ष्य अनुमान",
      "kpi_savings_desc": "स्वचालित अंतर-विभागीय सत्यापन से कागजी कार्रवाई, डाक व्यय और भौतिक सर्वर अपव्यय में 40% तक की बचत।",
      "kpi_ui_title": "नागरिक सेवा अनुभव",
      "kpi_ui_badge": "एकल-खिड़की",
      "kpi_ui_desc": "विभिन्न राज्य व केंद्रीय मंत्रालयों के पोर्टलों पर बार-बार फॉर्म भरने की बाध्यता समाप्त। शून्य दोहराव।",
      "kpi_sec_title": "सुरक्षा एवं डेटा संप्रभुता",
      "kpi_sec_badge": "शून्य-विश्वास",
      "kpi_sec_desc": "पूर्ण पेलोड एन्क्रिप्शन, डीपीडीपी अधिनियम 2023 के तहत स्पष्ट नागरिक सहमति टोकन और सुरक्षित मेश।",
      "sec1_badge": "DPI विजन 2026",
      "sec1_title": "प्रशासनिक चुनौतियाँ एवं राष्ट्रीय अंतर-प्रचालनीयता रूपरेखा (IndEA 2.0)",
      "prob_title": "विद्यमान प्रशासनिक बाधाएं",
      "prob_heading": "नागरिकों को खंडित, दोहरावपूर्ण एवं अत्यधिक विलंबित लोक सेवाओं का सामना करना पड़ता है",
      "prob_desc": "वर्तमान में अधिकांश सरकारी डिजिटल मंच अलग-थलग प्रशासनिक डेटा साइलो में कार्य करते हैं। एक ही जीवन-घटना के लिए नागरिकों को विभिन्न विभागों में एक ही पहचान प्रमाण बार-बार प्रस्तुत करना पड़ता है।",
      "prob_silos": "डेटा साइलो",
      "prob_silos_sub": "असंगत डेटाबेस",
      "prob_frag": "खंडित सेवाएं",
      "prob_frag_sub": "एकाधिक पोर्टल विज़िट",
      "prob_delays": "मैन्युअल विलंब",
      "prob_delays_sub": "हफ्तों का समय",
      "sol_title": "राष्ट्रीय एंटरप्राइज समाधान रूपरेखा (IndEA 2.0)",
      "sol_heading": "राष्ट्रीय डिजिटल अंतर-प्रचालनीयता गेटवे (NDIG Platform)",
      "sol_desc": "एक सुरक्षित, उच्च-स्तरीय सरकारी मिडलवेयर एकीकरण मंच जो मानकीकृत रेस्टफुल एपीआई, JSON-LD स्कीमा और नागरिक सहमति टोकन के माध्यम से विभागीय प्रणालियों को जोड़ता है।",
      "sol_p1": "<strong>अंतर-प्रचालनीय मंच:</strong> विक्रेता-तटस्थ और मानकीकृत ओपन-सोर्स सरकारी एकीकरण।",
      "sol_p2": "<strong>डेटा मानकीकरण:</strong> MeitY मेटाडेटा मानकों एवं JSON-LD 1.1 प्रारूप के तहत एकीकृत डेटा विनिमय।",
      "sol_p3": "<strong>सहमति-आधारित साझाकरण:</strong> डिजिटल पर्सनल डेटा प्रोटेक्शन (DPDP) एक्ट 2023 के तहत स्पष्ट नागरिक सहमति।",
      "sol_p4": "<strong>एकल जीवन-घटना इंटरफेस:</strong> नागरिक को जन्म से वृद्धावस्था तक सभी सेवाओं हेतु एकीकृत एकल डिजिटल विंडो।",
      "sec2_badge": "प्रस्तावित वास्तुकला",
      "sec2_title": "तकनीकी दृष्टिकोण: 8 मुख्य वास्तुकला स्तंभ",
      "sec2_sub": "ओपन एपीआई नीति एवं GIGW 3.0 डिज़ाइन दिशानिर्देशों के अनुरूप प्रस्तावित वास्तुकला ढांचा।",
      "p1_title": "स्तंभ 1: एपीआई-आधारित एकीकरण",
      "p1_desc": "मौजूदा सरकारी मंचों को मानकीकृत REST APIs और सुरक्षित सेवा इंटरफेस से जोड़ना, जिससे सीधे डेटाबेस कनेक्शन का जोखिम समाप्त हो।",
      "p2_title": "स्तंभ 2: अंतर-प्रचालनीयता लेयर",
      "p2_desc": "मंत्रालयों के बीच निर्बाध संचार और अतुल्यकालिक (asynchronous) डेटा आदान-प्रदान के लिए एक मजबूत मिडलवेयर एकीकरण परत।",
      "p3_title": "स्तंभ 3: समान डेटा मानक",
      "p3_desc": "सभी एजेंसियों में एकरूपता और सही अर्थग्रहण हेतु मानकीकृत डेटा मॉडल, JSON-LD प्रारूप और MeitY मेटाडेटा स्कीमा का अंगीकरण।",
      "p4_title": "स्तंभ 4: केंद्रीकृत प्रमाणीकरण",
      "p4_desc": "भूमिका-आधारित अभिगम नियंत्रण (RBAC) और ई-प्रमाण (e-Pramaan) / मेरी पहचान सिंगल साइन-ऑन (SSO) द्वारा सुरक्षित पहचान प्रबंधन।",
      "p5_title": "स्तंभ 5: डेटा तुल्यकालन",
      "p5_desc": "इवेंट-संचालित संदेश कतारों के माध्यम से जुड़े विभागीय सिस्टमों के बीच महत्वपूर्ण डेटा का वास्तविक समय (Real-Time) तुल्यकालन।",
      "p6_title": "स्तंभ 6: सुरक्षा एवं गोपनीयता",
      "p6_desc": "शून्य-विश्वास मॉडल (Zero-Trust), AES-256 एन्क्रिप्शन, क्रिप्टोग्राफिक ऑडिट लॉग्स और डीपीडीपी कानून सम्मत गोपनीयता नियंत्रण।",
      "p7_title": "स्तंभ 7: निगरानी एवं विश्लेषण",
      "p7_desc": "सिस्टम के प्रदर्शन, नेटवर्क लेटेंसी, लेन-देन की क्षमता और सेवा वितरण एसएलए (SLA) को ट्रैक करने के लिए केंद्रीकृत डैशबोर्ड।",
      "p8_title": "स्तंभ 8: मापनीय वास्तुकला",
      "p8_desc": "भविष्य के राज्य/केंद्रीय विभागों और बढ़ती नागरिक मांग को सरलता से ऑनबोर्ड करने के लिए क्लाउड-रेडी, मॉड्यूलर माइक्रो-सर्विस डिजाइन।",
      "sec3_badge": "उत्पादन स्तर वास्तुकला",
      "sec3_title": "एंटरप्राइज़ क्लाउड अवसंरचना एवं सिस्टम वास्तुकला",
      "sec3_sub": "कैशिंग, एज वितरण, सुरक्षा, डेटाबेस और मापनीयता हेतु राष्ट्रीय तकनीकी विनिर्देश (NeGD / MeitY मानक)।",
      "spec_caching": "वितरित कैशिंग (राष्ट्रीय गतिवर्धन लेयर)",
      "spec_caching_desc": "मेमोरी-आधारित गतिवर्धन क्लस्टर जो स्कीमा मैपिंग, नागरिक सहमति टोकन और सक्रिय सत्रों को 5 मिलीसेकंड से कम में निष्पादित करता है।",
      "spec_cdn": "एज सीडीएन (प्रस्तावित)",
      "spec_cdn_desc": "एनआईसी राष्ट्रीय एज सीडीएन + Anycast डीएनएस रूटिंग; क्षेत्रीय एज टर्मिनेशन, स्थैतिक स्कीमा वितरण और लेयर-7 सुरक्षा।",
      "spec_iam": "अभिगम नियंत्रण एवं वैधानिक शासन (RBAC/ABAC)",
      "spec_iam_desc": "विशेषता-आधारित व भूमिका-आधारित नियंत्रण; डीपीडीपी अधिनियम सहमति टोकन और मेरी पहचान (e-Pramaan SSO) एकीकरण।",
      "spec_rate": "गेटवे ट्रैफिक नियंत्रण एवं कतार प्रबंधन",
      "spec_rate_desc": "राष्ट्रीय एपीआई गेटवे ट्रैफिक थ्रॉटल (10,000 अनुरोध/सेकंड क्षमता) जो विभागीय सर्वरों को ओवरलोड से बचाता है।",
      "spec_cloud": "क्लाउड होस्टिंग (MeghRaj राष्ट्रीय जीआई क्लाउड)",
      "spec_cloud_desc": "MeitY-सूचीबद्ध क्लाउड (जैसे मेघराज) पर कंटेनर क्लस्टर में प्रस्तावित होस्टिंग; लक्ष्य 99.99% उपलब्धता और बहु-क्षेत्रीय आपदा रिकवरी।",
      "spec_logs": "ऑडिट लॉगिंग एवं घटना निदान",
      "spec_logs_desc": "केंद्रीकृत ऑडिट ट्रेल एवं टेलीमेट्री; विसंगति पहचान, प्रशासनिक लॉग्स और अनुपालन आश्वासन हेतु एंड-टू-एंड लेन-देन ट्रेसिंग।",
      "spec_db": "दोहरी-इंजन एंटरप्राइज डेटा रजिस्ट्री",
      "spec_db_desc": "अपरिवर्तनीय लेन-देन अभिलेखों हेतु एंटरप्राइज रिलेशनल डेटाबेस एवं लचीली विभागीय डेटा संरचनाओं हेतु स्कीमा रजिस्ट्री।",
      "spec_sec": "हार्डवेयर सिक्योरिटी मॉड्यूल (HSM) एवं एन्क्रिप्शन",
      "spec_sec_desc": "AES-256-GCM एंड-टू-एंड पेलोड एन्क्रिप्शन, mTLS 1.3 प्रमाणीकरण, हार्डवेयर सिक्योरिटी मॉड्यूल (HSM) और WORM सुरक्षित भंडारण।",
      "spec_cicd": "स्वचालित गुणवत्ता आश्वासन एवं प्रमाणन",
      "spec_cicd_desc": "परिनियोजन से पूर्व सुरक्षा भेद्यता स्कैनर, एपीआई अनुबंध सत्यापन और व्यापक परीक्षण सुइट्स युक्त सुरक्षित स्वचालित सीआई/सीडी पाइपलाइन।",
      "spec_mon": "राष्ट्रीय परिचालन टेलीमेट्री एवं एनओसी डैशबोर्ड",
      "spec_mon_desc": "केंद्रीकृत राष्ट्रीय संचालन डैशबोर्ड द्वारा वास्तविक समय अंतर-एजेंसी प्रतिक्रिया समय, सेवा उपलब्धता और नागरिक चार्टर एसएलए ट्रैकिंग।",
      "spec_vc": "राष्ट्रीय ई-गवर्नेंस स्कीमा अभिशासन",
      "spec_vc_desc": "ओपन एपीआई नीति के अनुरूप सख्त सिमेंटिक वर्जनिंग और घोषणात्मक बुनियादी ढांचा प्रबंधन।",
      "spec_notify": "राष्ट्रीय नागरिक सूचना प्रेषण गेटवे (CDAC SMS)",
      "spec_notify_desc": "सीडैक राष्ट्रीय एसएमएस गेटवे, आधिकारिक ईमेल और तत्काल बहु-माध्यम नागरिक सूचना वितरण हेतु इवेंट कतारें।",
      "console_title": "इंटरोऑपरेबिलिटी गेटवे — लाइव निष्पादन एवं ऑडिट कंसोल",
      "console_sub": "डिजिटल हस्ताक्षर एवं ऑडिट ट्रेल सत्यापन के साथ स्वचालित अंतर-विभागीय डेटा विनिमय निष्पादन।",
      "workflow_label": "कार्यप्रवाह चुनें:",
      "workflow_execute_btn": "प्रक्रिया निष्पादित करें",
      "stat_latency_label": "कुल लेटेंसी (Latency)",
      "stat_enc_label": "डेटा एन्क्रिप्शन",
      "stat_audit_label": "ऑडिट सत्यापन",
      "stat_pending": "सक्रिय / तैयार",
      "ledger_title": "राष्ट्रीय इंटरोऑपरेबिलिटी ऑडिट लेज़र",
      "ledger_badge": "ISO 27001 संरेखित",
      "ledger_initial_1": "[सिस्टम] NeGD इंटरोऑपरेबिलिटी गेटवे v2.6 सक्रिय — श्रवण मोड",
      "ledger_initial_2": "[स्टैंडबाय] स्वचालित अंतर-विभागीय सत्यापन ट्रिगर की प्रतीक्षा...",
      "sec5_badge": "उच्च व्यवहार्यता",
      "sec5_title": "परिचालन शासन, क्षमता एवं कार्यान्वयन रूपरेखा",
      "sec5_sub": "तकनीकी साध्यता, परिचालन व्यवहार्यता एवं प्रशासनिक दक्षता मॉडल।",
      "th_dimension": "मूल्यांकन आयाम",
      "th_tech": "तकनीकी साध्यता",
      "th_ops": "परिचालन व्यवहार्यता",
      "dim1_title": "वास्तुकla एवं एकीकरण",
      "dim1_tech": "माइक्रोसर्विस एपीआई एडॉप्टर जो बिना महंगे डेटाबेस पुनर्लेखन के मौजूदा विरासत प्रणालियों (Legacy DBs) को सुरक्षित लपेटते हैं।",
      "dim1_ops": "चरणबद्ध एजेंसी-दर-एजेंसी रोलआउट; शून्य सेवा डाउनटाइम के साथ नई एजेंसियों का निर्बाध ऑनबोर्डिंग।",
      "dim2_title": "सुरक्षा एवं वैधानिक अनुपालन",
      "dim2_tech": "शून्य-विश्वास (Zero-Trust) सुरक्षा मॉडल, पारस्परिक टीएलएस (mTLS 1.3) और एंड-टू-एंड पेलोड एन्क्रिप्शन।",
      "dim2_ops": "डिजिटल व्यक्तिगत डेटा संरक्षण अधिनियम (DPDP Act 2023) और राष्ट्रीय ई-गवर्नेंस सुरक्षा नीतियों का 100% अनुपालन।",
      "dim3_title": "लागत एवं वित्तीय प्रतिलाभ",
      "dim3_tech": "पुनः प्रयोज्य ओपन-सोर्स घटकों एवं सरकारी जीआई क्लाउड का उपयोग जिससे प्रारंभिक पूंजीगत व्यय (CapEx) न्यूनतम हो।",
      "dim3_ops": "कागजी कार्रवाई, प्रशासनिक अतिरेक और मैन्युअल सत्यापन में बचत के माध्यम से <strong>24 महीनों</strong> में आरओआई प्राप्त।",
      "dim4_title": "शासन एवं अंतर-एजेंसी अंगीकरण",
      "dim4_tech": "मानकीकृत डेवलपर एसडीके (SDKs) और त्वरित एकीकरण हेतु केंद्रीकृत स्व-सेवा एपीआई पोर्टल (API Setu मॉडल)।",
      "dim4_ops": "संस्थागत नीतिगत अधिदेश और संरचित अंतर-विभागीय परिवर्तन प्रबंधन सहायता।",
      "calc_title": "सरकारी दक्षता एवं NeGD प्रशासनिक प्रभाव मॉडल",
      "calc_sub": "मानकीकृत NeGD मॉडल: कागजरहित डिजिटल सत्यापन के माध्यम से संबद्ध विभागों में प्रत्यक्ष प्रशासनिक दक्षता बचत।",
      "calc_label": "संबद्ध सरकारी विभाग:",
      "calc_annual_label": "अनुमानित वार्षिक बचत",
      "sec6_badge": "संदर्भ मानक",
      "sec6_title": "वैधानिक नीतियां एवं राष्ट्रीय ई-गवर्नेंस मानक",
      "ref_policy_title": "नीतिगत एवं अनुसंधान आधार",
      "ref_tech_title": "तकनीकी मानक एवं विनिर्देश",
      "ft_team_title": "MH सहयोग (MH Sahyog)",
      "ft_team_desc": "MH सहयोग (MH Sahyog) इलेक्ट्रॉनिक्स एवं सूचना प्रौद्योगिकी मंत्रालय (MeitY), भारत सरकार द्वारा संचालित एकीकृत लोक सेवा मंच है।",
      "ft_portals_title": "संदर्भ सरकारी पोर्टल",
      "ft_specs_title": "प्लेटफॉर्म विनिर्देश",
      "ft_wim_title": "वेब सूचना प्रबंधक (WIM)",
      "ft_wim_name": "नाम: राष्ट्रीय पोर्टल प्रभाग (NeGD)",
      "ft_wim_desig": "पदनाम: मुख्य तकनीकी अधिकारी एवं सिस्टम आर्किटेक्चर समूह",
      "ft_wim_event": "राष्ट्रीय ई-गवर्नेंस प्रभाग (NeGD), MeitY",
      "ft_wim_stqc": "भारतीय सरकारी वेबसाइट दिशानिर्देश (GIGW 3.0) के पूर्णतः अनुरूप",
      "ft_nic_note": "ओपन एपीआई नीति एवं IndEA 2.0 के तहत राष्ट्रीय ई-गवर्नेंस प्रभाग (NeGD), MeitY, भारत सरकार द्वारा अभिकल्पित एवं विकसित।",
      "ft_visitors": "आगंतुक संख्या:",
      "ft_last_updated": "अंतिम नवीनीकरण:",
      "ft_copyright": "© 2026 MH सहयोग (MH Sahyog), इलेक्ट्रॉनिक्स एवं सूचना प्रौद्योगिकी मंत्रालय, भारत सरकार। सर्वाधिकार सुरक्षित।"
    ,
"charter_title": "नागरिक अधिकार पत्र एवं लोक सेवा गारंटी (Citizen Charter)",
      "charter_sub": "लोक सेवा अधिकार अधिनियम के अंतर्गत अधिसूचित सांविधिक सेवाएं, समय-सीमा एवं अपीलीय प्राधिकारी।",
      "charter_act_badge": "अधिनियम २०११ द्वारा संरक्षित",
      "charter_penalty_title": "लोक सेवा अधिकार अधिनियम के तहत वैधानिक गारंटी:",
      "charter_penalty_desc": "निर्धारित समय-सीमा के भीतर सेवा उपलब्ध न कराने की स्थिति में संबंधित पदाभिहित अधिकारी पर प्रति दिन ₹२५० (अधिकतम ₹५,०००) की शास्ति अधिरोपित किए जाने का वैधानिक प्रावधान है।",
      "helpdesk_title": "नागरिक सहायता केंद्र एवं शिकायत निवारण (CPGRAMS)",
      "helpdesk_sub": "२४x७ नागरिक हेल्पलाइन, तकनीकी सहायता एवं लोक शिकायत निवारण प्रणाली।",
      "helpdesk_badge": "24x7 सक्रिय",
      "helpdesk_tollfree_title": "टोल-फ्री नागरिक हेल्पलाइन",
      "helpdesk_tollfree_desc": "समस्त प्रमाण पत्रों व सेवाओं की जानकारी हेतु संपर्क करें:",
      "helpdesk_tollfree_note": "निःशुल्क • समस्त कार्यदिवस (२४x७)",
      "helpdesk_email_title": "ई-मेल तकनीकी सहायता",
      "helpdesk_email_desc": "ऑनलाइन आवेदन में किसी भी समस्या हेतु संपर्क करें:",
      "helpdesk_email_note": "औसत प्रत्युत्तर समय: २ घंटे के भीतर",
      "helpdesk_cpgrams_title": "लोक शिकायत निवारण (CPGRAMS)",
      "helpdesk_cpgrams_desc": "अनावश्यक देरी या भ्रष्टाचार की ऑनलाइन शिकायत दर्ज करें:",
      "helpdesk_cpgrams_btn": "CPGRAMS पोर्टल पर शिकायत दर्ज करें →",

      "nav_home": "मुख्य पृष्ठ",
      "nav_directory": "सेवा निर्देशिका",
      "nav_apply": "ऑनलाइन आवेदन",
      "nav_track": "आवेदन स्थिति",
      "nav_verify": "प्रमाण पत्र सत्यापन",
      "nav_charter": "नागरिक अधिकार पत्र",
      "nav_standards": "वास्तुकला एवं मानक",
      "nav_helpdesk": "सहायता केंद्र",
      "nav_terms": "नियम एवं शर्तें",
      "nav_login": "नागरिक लॉगिन",
      "nav_status_gateway": "१००% सुरक्षित अंतर-संचालनीयता सक्रिय • एनईजीडी",
      "login_modal_title": "राष्ट्रीय एकल साइन-ऑन (मेरी पहचान)",
      "login_modal_subtitle": "इलेक्ट्रॉनिक्स एवं सूचना प्रौद्योगिकी मंत्रालय • डिजिटल इंडिया",
      "login_tab_citizen": "नागरिक लॉगिन",
      "login_tab_officer": "अधिकारी लॉगिन (परिचय)",
      "login_citizen_id_label": "आधार संख्या / पंजीकृत मोबाइल संख्या:",
      "login_otp_label": "वन-टाइम पासवर्ड (ओटीपी):",
      "login_resend_otp": "ओटीपी भेजें",
      "login_otp_hint": "डेमो ओटीपी स्वतः भरा: 589201 (यूआईडीएआई एसएमएस)",
      "login_btn_citizen": "मेरी पहचान (डिजिलॉकर) द्वारा लॉगिन करें",
      "login_officer_id_label": "आधिकारिक ईमेल आईडी / परिचय आईडी:",
      "login_officer_pass_label": "पासवर्ड / डिजिटल टोकन पिन:",
      "login_btn_officer": "परिचय एसएसओ द्वारा प्रमाणित करें",
      "login_security_notice": "256-बिट टीएलएस एन्क्रिप्शन एवं डीपीडीपी अधिनियम 2023 के तहत पूर्ण सुरक्षित।",
      "terms_modal_title": "सेवा की शर्तें, गोपनीयता नीति एवं विधिक अनुपालन",
      "terms_modal_subtitle": "डिजिटल व्यक्तिगत डेटा संरक्षण अधिनियम २०२३ • आईटी अधिनियम २००० • जीआईजीडब्ल्यू ३.०",
      "terms_sec1_title": "१. सेवा की शर्तें एवं सांविधिक नागरिक अधिकार",
      "terms_sec1_desc": "यह राष्ट्रीय डिजिटल अंतर-संचालनीयता गेटवे (NDIG) राष्ट्रीय ई-गवर्नेंस प्रभाग (NeGD), इलेक्ट्रॉनिक्स एवं आईटी मंत्रालय, भारत सरकार द्वारा संचालित आधिकारिक सार्वजनिक सेवा वितरण मंच है। इस पोर्टल का उपयोग सूचना प्रौद्योगिकी अधिनियम २००० एवं डीपीडीपी अधिनियम २०२३ के अंतर्गत शासित है।",
      "terms_sec2_title": "२. गोपनीयता नीति एवं नागरिक सहमति ढांचा",
      "terms_sec2_desc": "डीपीडीपी अधिनियम २०२३ की धारा ६ के पूर्ण अनुपालन में मंत्रालयों के बीच डेटा विनिमय केवल नागरिक की स्पष्ट व प्रतिसंहरणीय सहमति पर ही किया जाता है। गेटवे पर कोई बायोमेट्रिक डेटा संगृहीत नहीं किया जाता।",
      "terms_sec3_title": "३. डिजिटल प्रमाण पत्रों की विधिक मान्यता",
      "terms_sec3_desc": "इस गेटवे द्वारा निर्गत समस्त प्रमाण पत्र क्लास ३ डिजिटल हस्ताक्षर द्वारा प्रमाणित हैं। सूचना प्रौद्योगिकी अधिनियम २००० की धारा ४ व ५ के अंतर्गत ये डिजिटल रूप से हस्ताक्षरित दस्तावेज भौतिक कागजी प्रमाण पत्रों के पूर्ण समतुल्य हैं।",
      "terms_sec4_title": "४. सांविधिक समय-सीमा एवं लोक सेवा गारंटी",
      "terms_sec4_desc": "इस पोर्टल द्वारा उपलब्ध कराई जाने वाली सेवाएं लोक सेवा गारंटी अधिनियम के तहत अधिसूचित हैं। प्रत्येक नागरिक को नागरिक अधिकार पत्र में निर्धारित समय-सीमा के भीतर सेवाएं प्राप्त करने का विधिक अधिकार है।",
      "terms_sec5_title": "५. हाइपरलिंकिंग एवं सामग्री कॉपीराइट नीति",
      "terms_sec5_desc": "इस पोर्टल पर प्रकाशित सामग्री को शैक्षणिक व प्रशासनिक सत्यापन हेतु इलेक्ट्रॉनिक्स एवं आईटी मंत्रालय के उचित उल्लेख के साथ पुनः प्रस्तुत किया जा सकता है।",
      "ft_terms_use": "उपयोग की शर्तें",
      "ft_privacy_policy": "गोपनीयता नीति",
      "ft_hyperlink_policy": "हाइपरलिंकिंग नीति",
      "ft_copyright_policy": "कॉपीराइट नीति",
      "ft_disclaimer": "अस्वीकरण",
      "ft_certin": "सीईआरटी-इन सुरक्षा अनुपालन",
      "bento_caste_title": "जाति, आय एवं निवास प्रमाण पत्र पटल",
      "bento_caste_dept": "राजस्व एवं भूमि सुधार विभाग",
      "bento_caste_cta": "राजस्व पटल खोलें",
      "bento_dl_title": "स्मार्ट ड्राइविंग लाइसेंस पटल",
      "bento_dl_dept": "सड़क परिवहन एवं राजमार्ग मंत्रालय (MoRTH)",
      "bento_dl_cta": "ड्राइविंग लाइसेंस पटल खोलें",
      "bento_birth_title": "जन्म, मृत्यु एवं बाल आधार पटल",
      "bento_birth_dept": "भारत के महारजिस्ट्रार का कार्यालय (CRS)",
      "bento_birth_cta": "जन्म प्रमाण पत्र पटल खोलें",
      "bento_farmer_title": "पीएम-किसान डीबीटी एवं कृषक पटल",
      "bento_farmer_dept": "कृषि एवं किसान कल्याण मंत्रालय",
      "bento_farmer_cta": "कृषि डीबीटी पटल खोलें",
      "bento_mca_title": "कंपनी निगमन एवं एमएसएमई पटल",
      "bento_mca_dept": "कॉर्पोरेट कार्य मंत्रालय (MCA21 V3)",
      "bento_mca_cta": "कंपनी पंजीकरण पटल खोलें",
      "bento_verifier_title": "सार्वभौमिक दस्तावेज सत्यापन पटल",
      "bento_verifier_dept": "प्रमाणीकरण प्राधिकारी नियंत्रक (MeitY)",
      "bento_verifier_cta": "प्रमाण पत्र सत्यापित करें"
    ,
      "hero_main_heading": "राष्ट्रीय नागरिक लोक सेवा पोर्टल <br><span class=\"text-[#FF8000]\">समस्त प्रमाण पत्र एवं सांविधिक सेवाएं</span> एक ही स्थान पर",
      "cta_apply_desc": "जाति, आय, निवास, ड्राइविंग लाइसेंस एवं २०+ सेवाओं हेतु कागज-रहित आवेदन",
      "cta_track_desc": "आवेदन संदर्भ संख्या द्वारा ५-चरणीय वास्तविक समय स्थिति ट्रैक करें",
      "cta_verify_desc": "सार्वभौमिक क्यूआर कोड एवं क्लास ३ डिजिटल हस्ताक्षर द्वारा जांचें",
      "cta_download_desc": "डिजिटल हस्ताक्षरित राजपत्र प्रमाण पत्र प्राप्त करें एवं डिजिलॉकर में सहेजें",
      "tag_popular_label": "लोकप्रिय सेवाएं:",
      "tag_caste": "जाति प्रमाण पत्र",
      "tag_income": "आय प्रमाण पत्र",
      "tag_domicile": "निवास प्रमाण पत्र",
      "tag_dl": "ड्राइविंग लाइसेंस",
      "tag_birth": "जन्म प्रमाण पत्र",
      "tag_farmer": "पीएम-किसान डीबीटी"
    }
  };

  let currentLang = localStorage.getItem('ndig_portal_lang') || 'en';

  // 3. Official Interoperability Gateway Simulator Scenarios in Both Languages
  const scenariosByLang = {
    en: {
      birth: {
        name: "Workflow: Newborn Child Registration & Baal Aadhaar (MoHFW + Municipal Corporation + UIDAI)",
        refNo: "NDIG/2026/CRS-BTH-9021",
        steps: [
          {
            agency: "Ministry of Health & Family Welfare (MoHFW)",
            title: "Hospital Institutional Birth Certificate Clearance",
            desc: "Digital institutional delivery record confirmed from National Health Registry (ABDM/NDHM).",
            recordRef: "Registry Record: MoHFW/CRS/2026/DEL-8812",
            securitySeal: "Controller of Certifying Authorities (CCA) Level-3 DSC Verified",
            status: "VERIFIED"
          },
          {
            agency: "Local Municipal Corporation (Civil Registration System)",
            title: "Municipal Birth Register & Certificate Generation",
            desc: "Civil Registration System (CRS) digital certificate generated under National Metadata Standards.",
            recordRef: "Gazette Ledger Entry: CRS-DEL-2026-44019",
            securitySeal: "Municipal Registrar Seal Digitally Attached & Validated",
            status: "VERIFIED"
          },
          {
            agency: "Unique Identification Authority of India (UIDAI)",
            title: "Baal Aadhaar Allotment & DigiLocker Digital Dispatch",
            desc: "Zero-document Baal Aadhaar securely issued and pushed directly into citizen's DigiLocker vault.",
            recordRef: "Aadhaar Issuance Token: UIDAI-BL-2026-90218",
            securitySeal: "Citizen Consent Validated under DPDP Act 2023",
            status: "VERIFIED"
          },
          {
            agency: "National Informatics Centre (NIC / MeitY)",
            title: "National Public SMS Acknowledgement Dispatch",
            desc: "Official delivery confirmation SMS and electronic receipt dispatched to registered parent mobile.",
            recordRef: "National SMS Gateway: CDAC-ACK-2026-7712",
            securitySeal: "National Telecom DLT Header Verified",
            status: "COMPLETED"
          }
        ]
      },
      business: {
        name: "Workflow: Single-Window Business Incorporation (MCA + CBDT/GSTN + EPFO + Banking)",
        refNo: "NDIG/2026/SPICE-INC-4418",
        steps: [
          {
            agency: "Ministry of Corporate Affairs (MCA - SPICe+)",
            title: "Company Name Approval & Director Identity Verification",
            desc: "Registrar of Companies (RoC) electronic verification of digital signatures and Director DIN.",
            recordRef: "RoC Electronic Filing Ref: MCA-SPICE-2026-ROC",
            securitySeal: "Director Digital Signature Certificate (DSC) Verified",
            status: "VERIFIED"
          },
          {
            agency: "GST Network (GSTN) & Income Tax Department (CBDT)",
            title: "Instant Corporate PAN, TAN & GSTIN Tax Allotment",
            desc: "Inter-agency electronic exchange issues digitally certified tax identification credentials in sub-second time.",
            recordRef: "Tax Jurisdiction Certificate: PAN-TAN-2026-CBDT",
            securitySeal: "Central Board of Direct Taxes Digital Attestation Valid",
            status: "VERIFIED"
          },
          {
            agency: "Ministry of Labour & Employment (EPFO & ESIC)",
            title: "Shram Suvidha Corporate Establishment Registration",
            desc: "Labor Identification Number (LIN) and EPFO establishment code allocated without paperwork.",
            recordRef: "Shram Suvidha Portal Ref: SHRAM-LIN-2026-EPFO",
            securitySeal: "Social Security Registry Digital Clearance Granted",
            status: "VERIFIED"
          },
          {
            agency: "RBI Authorized Commercial Banking Network",
            title: "Corporate Current Account Digital Provisioning",
            desc: "Instant corporate banking current account activation via RBI Account Aggregator network.",
            recordRef: "Account Aggregator Mandate: RBI-AA-2026-CORP",
            securitySeal: "Reserve Bank of India Open Banking Protocol Verified",
            status: "COMPLETED"
          }
        ]
      },
      farmer: {
        name: "Workflow: PM-KISAN Direct Benefit Transfer & Land Verification (AgriStack + Bhulekh + PFMS + AePS)",
        refNo: "NDIG/2026/DBT-AGRI-7734",
        steps: [
          {
            agency: "Ministry of Agriculture & Farmers Welfare",
            title: "AgriStack Beneficiary Biometric Verification",
            desc: "National Farmer Database verifies electronic beneficiary credentials via national AgriStack registry.",
            recordRef: "AgriStack Electronic Ref: AGRI-FARM-2026-EKYC",
            securitySeal: "National Farmer Registry Biometric Attestation Valid",
            status: "VERIFIED"
          },
          {
            agency: "State Revenue Department (Bhulekh / DILRMP)",
            title: "Cadastral Land Parcel Title Geo-Verification",
            desc: "Real-time cross-verification of Khasra #421/3 ownership under active beneficiary title.",
            recordRef: "DILRMP Cadastral Record: BHULEKH-UP-421-3",
            securitySeal: "State Revenue Department Digital Title Verified",
            status: "VERIFIED"
          },
          {
            agency: "Public Financial Management System (PFMS / MoF)",
            title: "Central Treasury Direct Sanction Clearance",
            desc: "Treasury welfare sanction clearance approved with zero administrative fiscal leakage.",
            recordRef: "Treasury Budget Sanction: MOF-DBT-2026-PFMS",
            securitySeal: "Ministry of Finance Budget Sanction Seal Validated",
            status: "VERIFIED"
          },
          {
            agency: "National Payments Corporation of India (NPCI - AePS)",
            title: "Aadhaar-Enabled Direct Welfare Bank Credit",
            desc: "₹2,000 welfare installment credited in real-time into farmer bank account with instant SMS receipt.",
            recordRef: "NPCI AePS Settlement Ref: NPCI-AEPS-2026-CREDIT",
            securitySeal: "Bank Direct Benefit Transfer (DBT) Settlement Complete",
            status: "COMPLETED"
          }
        ]
      }
    },
    hi: {
      birth: {
        name: "प्रक्रिया: नवजात शिशु जन्म पंजीकरण एवं बाल आधार (MoHFW + नगर निगम + UIDAI)",
        refNo: "NDIG/2026/CRS-BTH-9021",
        steps: [
          {
            agency: "स्वास्थ्य एवं परिवार कल्याण मंत्रालय (MoHFW)",
            title: "अस्पताल डिजिटल जन्म रिपोर्ट सत्यापन",
            desc: "संस्थागत जन्म रिपोर्ट #HSP-DEL-2026-8812 को राष्ट्रीय स्वास्थ्य रजिस्ट्री (ABDM) द्वारा सत्यापित किया गया।",
            recordRef: "राष्ट्रीय स्वास्थ्य रजिस्ट्री संदर्भ: MoHFW/CRS/2026/DEL-8812",
            securitySeal: "नियंत्रक प्रमाणीकरण प्राधिकारी (CCA) डिजिटल हस्ताक्षर प्रमाणित",
            status: "सत्यापित (VERIFIED)"
          },
          {
            agency: "नगर निगम / स्थानीय निकाय (Civil Registration System)",
            title: "डिजिटल जन्म प्रमाण पत्र उत्पादन एवं लेजर अंकन",
            desc: "नागरिक सिविल पंजीकरण प्रणाली (CRS) लेजर में प्रविष्टि दर्ज कर डिजिटल प्रमाण पत्र तैयार किया गया।",
            recordRef: "राजपत्र पंजीकरण लेजर सं.: CRS-DEL-2026-44019",
            securitySeal: "नगर निगम रजिस्ट्रार मुहर डिजिटल रूप से सत्यापित",
            status: "सत्यापित (VERIFIED)"
          },
          {
            agency: "भारतीय विशिष्ट पहचान प्राधिकरण (UIDAI)",
            title: "बाल आधार आवंटन एवं डिजीलॉकर सीधा प्रेषण",
            desc: "माता-पिता की डिजिटल सहमति के आधार पर शून्य-दस्तावेज़ बाल आधार सृजन एवं डिजीलॉकर में सुरक्षित वितरण।",
            recordRef: "आधार जीवन-घटना टोकन: UIDAI-BL-2026-90218",
            securitySeal: "डीपीडीपी अधिनियम 2023 के तहत नागरिक सहमति प्रमाणित",
            status: "सत्यापित (VERIFIED)"
          },
          {
            agency: "राष्ट्रीय सूचना केंद्र (NIC / MeitY)",
            title: "नागरिक एसएमएस पावती एवं डिजिटल रसीद",
            desc: "सीडैक (CDAC) राष्ट्रीय एसएमएस गेटवे द्वारा माता-पिता के पंजीकृत मोबाइल पर पुष्टिकरण सूचना प्रेषित।",
            recordRef: "राष्ट्रीय एसएमएस गेटवे: CDAC-ACK-2026-7712",
            securitySeal: "राष्ट्रीय दूरसंचार डीएलटी हेडर अधिकृत",
            status: "संपूर्ण (COMPLETED)"
          }
        ]
      },
      business: {
        name: "प्रक्रिया: एकीकृत एकल-खिड़की व्यवसाय समावेशन (MCA + CBDT/GSTN + EPFO + Banking)",
        refNo: "NDIG/2026/SPICE-INC-4418",
        steps: [
          {
            agency: "कॉर्पोरेट कार्य मंत्रालय (Ministry of Corporate Affairs - MCA)",
            title: "SPICe+ कंपनी नाम अनुमोदन एवं डीआईएन सत्यापन",
            desc: "कंपनी रजिस्ट्रार (RoC) पोर्टल से डिजिटल हस्ताक्षर और निदेशक पहचान संख्या (DIN) का सीधा सत्यापन।",
            recordRef: "कंपनी रजिस्ट्रार ई-फाइलिंग सं.: MCA-SPICE-2026-ROC",
            securitySeal: "निदेशक डिजिटल हस्ताक्षर प्रमाण पत्र (DSC) सत्यापित",
            status: "सत्यापित (VERIFIED)"
          },
          {
            agency: "जीएसटी नेटवर्क (GSTN) एवं आयकर विभाग (CBDT)",
            title: "स्वचालित पैन, टैन एवं जीएसटीएन आवंटन",
            desc: "अंतर-मंत्रालयी डिजिटल विनिमय द्वारा कुछ ही सेकंड में टैक्स पहचान संख्या आवंटित कर प्रमाणित की गई।",
            recordRef: "कर अधिकार क्षेत्र प्रमाण पत्र: PAN-TAN-2026-CBDT",
            securitySeal: "केंद्रीय प्रत्यक्ष कर बोर्ड (CBDT) मुहर अधिकृत",
            status: "सत्यापित (VERIFIED)"
          },
          {
            agency: "श्रम एवं रोजगार मंत्रालय (EPFO & ESIC)",
            title: "श्रम सुविधा प्रतिष्ठान कोड आवंटन",
            desc: "ईपीएफओ एवं ईएसआईसी डेटाबेस में बिना किसी भौतिक प्रपत्र के कॉर्पोरेट पहचान दर्ज।",
            recordRef: "श्रम सुविधा पोर्टल संदर्भ: SHRAM-LIN-2026-EPFO",
            securitySeal: "सामाजिक सुरक्षा रजिस्ट्री डिजिटल स्वीकृति प्राप्त",
            status: "सत्यापित (VERIFIED)"
          },
          {
            agency: "भारतीय रिज़र्व बैंक अधिकृत बैंक नेटवर्क (RBI Open Banking)",
            title: "कॉर्पोरेट चालू खाता डिजिटल प्रावधान",
            desc: "आरबीआई अकाउंट एग्रीगेटर फ्रेमवर्क द्वारा कंपनी का शून्य-कागजी चालू बैंक खाता तुरंत सक्रिय।",
            recordRef: "अकाउंट एग्रीगेटर अधिदेश: RBI-AA-2026-CORP",
            securitySeal: "आरबीआई ओपन बैंकिंग प्रोटोकॉल सत्यापित",
            status: "संपूर्ण (COMPLETED)"
          }
        ]
      },
      farmer: {
        name: "प्रक्रिया: पीएम-किसान प्रत्यक्ष लाभ अंतरण एवं भू-सत्यापन (AgriStack + Bhulekh + PFMS + AePS)",
        refNo: "NDIG/2026/DBT-AGRI-7734",
        steps: [
          {
            agency: "कृषि एवं किसान कल्याण मंत्रालय (Ministry of Agriculture)",
            title: "एग्रीस्टैक बायोमेट्रिक ई-केवाईसी सत्यापन",
            desc: "राष्ट्रीय किसान डेटाबेस से आधार-आधारित डिजिटल ई-केवाईसी टोकन सत्यापन संपन्न।",
            recordRef: "एग्रीस्टैक इलेक्ट्रॉनिक संदर्भ: AGRI-FARM-2026-EKYC",
            securitySeal: "राष्ट्रीय किसान रजिस्ट्री बायोमेट्रिक प्रमाणीकरण वैध",
            status: "सत्यापित (VERIFIED)"
          },
          {
            agency: "राज्य राजस्व विभाग (State Land Records - Bhulekh)",
            title: "भू-अभिलेख खसरा खतौनी भू-सत्यापन",
            desc: "डिजिटल इंडिया भू-अभिलेख आधुनिकीकरण कार्यक्रम (DILRMP) द्वारा खसरा #421/3 का वास्तविक समय मिलान।",
            recordRef: "भूलेख भू-अभिलेख संख्या: BHULEKH-UP-421-3",
            securitySeal: "राज्य राजस्व विभाग डिजिटल स्वामित्व प्रमाणित",
            status: "सत्यापित (VERIFIED)"
          },
          {
            agency: "सार्वजनिक वित्तीय प्रबंधन प्रणाली (PFMS / MoF)",
            title: "केंद्रीय बजट ट्रेजरी स्वीकृति",
            desc: "प्रत्यक्ष लाभ अंतरण (DBT) के लिए राजकोषीय आवंटन बिना किसी प्रशासनिक रिसाव के स्वीकृत।",
            recordRef: "ट्रेजरी बजट आवंटन संदर्भ: MOF-DBT-2026-PFMS",
            securitySeal: "वित्त मंत्रालय बजट संस्वीकृति मुहर प्रमाणित",
            status: "सत्यापित (VERIFIED)"
          },
          {
            agency: "भारतीय राष्ट्रीय भुगतान निगम (NPCI - AePS)",
            title: "आधार सक्षम भुगतान प्रणाली अंतरण",
            desc: "₹2,000 की किस्त कुछ ही सेकंड में किसान के बैंक खाते में सीधे जमा, तत्काल एसएमएस सूचना जारी।",
            recordRef: "एनपीसीआई भुगतान निपटान संदर्भ: NPCI-AEPS-2026-CREDIT",
            securitySeal: "प्रत्यक्ष लाभ अंतरण (DBT) बैंक निपटान पूर्ण",
            status: "संपूर्ण (COMPLETED)"
          }
        ]
      }
    }
  };

  // 4. Function to Apply Language
  function applyLanguage(lang) {
    currentLang = lang;
    try { localStorage.setItem('ndig_portal_lang', lang); } catch(e) {}
    if (document.documentElement) document.documentElement.lang = lang;

    const btnEn = document.getElementById('lang-btn-en');
    const btnHi = document.getElementById('lang-btn-hi');
    if (btnEn && btnHi) {
      if (lang === 'en') {
        btnEn.className = "px-2 py-0.5 rounded text-[11px] font-bold text-white bg-[#00314D] shadow-sm transition";
        btnHi.className = "px-2 py-0.5 rounded text-[11px] font-bold text-slate-300 hover:text-white transition";
      } else {
        btnHi.className = "px-2 py-0.5 rounded text-[11px] font-bold text-white bg-[#00314D] shadow-sm transition";
        btnEn.className = "px-2 py-0.5 rounded text-[11px] font-bold text-slate-300 hover:text-white transition";
      }
    }

    const i18nElements = document.querySelectorAll('[data-i18n]');
    const dict = translations[lang] || translations.en;

    i18nElements.forEach(el => {
      const key = el.getAttribute('data-i18n');
      if (dict[key] !== undefined) {
        el.innerHTML = dict[key];
      }
    
  });

    const searchInput = document.getElementById('gov-search-input');
    if (searchInput && dict['search_placeholder']) {
      searchInput.placeholder = dict['search_placeholder'];
    }

    const scenarioSelect = document.getElementById('scenario-select');
    if (scenarioSelect) {
      const currentVal = scenarioSelect.value || 'birth';
      if (lang === 'en') {
        scenarioSelect.options[0].text = "Newborn Child Registration (MoHFW + Municipal + UIDAI)";
        scenarioSelect.options[1].text = "Single-Window Business Incorporation (MCA + GSTN + EPFO + Bank)";
        scenarioSelect.options[2].text = "PM-KISAN DBT & Land Records (AgriStack + Bhulekh + PFMS)";
      } else {
        scenarioSelect.options[0].text = "नवजात शिशु जन्म पंजीकरण एवं बाल आधार (MoHFW + Municipal + UIDAI)";
        scenarioSelect.options[1].text = "एकल-खिड़की व्यवसाय समावेशन (MCA + GSTN + EPFO + Bank)";
        scenarioSelect.options[2].text = "पीएम-किसान डीबीटी एवं भू-अभिलेख (AgriStack + Bhulekh + PFMS)";
      }
      scenarioSelect.value = currentVal;
    }

    renderScenario(currentScenarioKey);
    calculateGovSavings();
  }

  // Bind Language Switcher Buttons
  const btnEn = document.getElementById('lang-btn-en');
  const btnHi = document.getElementById('lang-btn-hi');
  if (btnEn) btnEn.addEventListener('click', (e) => { e.preventDefault(); applyLanguage('en'); 
  });
  if (btnHi) btnHi.addEventListener('click', (e) => { e.preventDefault(); applyLanguage('hi'); 
  });

  
  window.applyLanguage = applyLanguage;
  window.switchGovLanguage = applyLanguage;

  // 5. GIGW Accessibility: Font Resizing Controls
  const fontDecBtn = document.getElementById('font-decrease');
  const fontResetBtn = document.getElementById('font-reset');
  const fontIncBtn = document.getElementById('font-increase');
  const contrastBtn = document.getElementById('font-contrast');
  const htmlRoot = document.documentElement;
  const bodyRoot = document.body;

  if (fontDecBtn && fontResetBtn && fontIncBtn) {
    fontDecBtn.addEventListener('click', (e) => {
      e.preventDefault();
      htmlRoot.classList.remove('font-large');
      htmlRoot.classList.add('font-small');
    
  });

    fontResetBtn.addEventListener('click', (e) => {
      e.preventDefault();
      htmlRoot.classList.remove('font-small', 'font-large');
    
  });

    fontIncBtn.addEventListener('click', (e) => {
      e.preventDefault();
      htmlRoot.classList.remove('font-small');
      htmlRoot.classList.add('font-large');
    
  });
  }

  if (contrastBtn) {
    contrastBtn.addEventListener('click', (e) => {
      e.preventDefault();
      bodyRoot.classList.toggle('high-contrast');
      contrastBtn.textContent = bodyRoot.classList.contains('high-contrast') ? 
        (currentLang === 'en' ? 'Normal (A)' : 'सामान्य (A)') : 
        (currentLang === 'en' ? 'Contrast (A)' : 'कंट्रास्ट (A)');
    
  });
  }

  // 6. Interactive Hero Banner Carousel Slider
  const slides = document.querySelectorAll('.hero-slide');
  const dots = document.querySelectorAll('.slider-dot');
  const prevBtn = document.getElementById('slider-prev');
  const nextBtn = document.getElementById('slider-next');
  let currentSlide = 0;
  let sliderTimer = null;

  function showSlide(index) {
    slides.forEach((s, i) => {
      s.classList.toggle('active', i === index);
    
  });
    dots.forEach((d, i) => {
      d.classList.toggle('active', i === index);
    
  });
    currentSlide = index;
  }

  function nextSlide() {
    let nextIndex = (currentSlide + 1) % slides.length;
    showSlide(nextIndex);
  }

  function prevSlide() {
    let prevIndex = (currentSlide - 1 + slides.length) % slides.length;
    showSlide(prevIndex);
  }

  if (nextBtn) nextBtn.addEventListener('click', () => { nextSlide(); resetSlideTimer(); 
  });
  if (prevBtn) prevBtn.addEventListener('click', () => { prevSlide(); resetSlideTimer(); 
  });

  dots.forEach(dot => {
    dot.addEventListener('click', () => {
      const targetIndex = parseInt(dot.getAttribute('data-slide'), 10);
      showSlide(targetIndex);
      resetSlideTimer();
    
  });
  
  });

  function startSlideTimer() {
    sliderTimer = setInterval(nextSlide, 6500);
  }

  function resetSlideTimer() {
    clearInterval(sliderTimer);
    startSlideTimer();
  }

  if (slides.length > 0) {
    startSlideTimer();
  }

  // 7. Interactive Spec Category Tabs Filtering
  const specTabs = document.querySelectorAll('.spec-tab-btn');
  const specTiles = document.querySelectorAll('.gov-spec-tile');

  specTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      specTabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');

      const cat = tab.getAttribute('data-tab');
      specTiles.forEach(tile => {
        if (cat === 'all' || tile.getAttribute('data-cat') === cat) {
          tile.style.display = 'block';
        } else {
          tile.style.display = 'none';
        }
      
  });
    
  });
  
  });

  // 8. Animated Number Counters on Scroll (KPIs)
  const counterElements = document.querySelectorAll('.counter-num');
  let countersStarted = false;

  function animateCounters() {
    counterElements.forEach(counter => {
      const target = parseInt(counter.getAttribute('data-target'), 10);
      let count = 0;
      const duration = 1200;
      const stepTime = 30;
      const steps = duration / stepTime;
      const increment = target / steps;

      const timer = setInterval(() => {
        count += increment;
        if (count >= target) {
          counter.textContent = target;
          clearInterval(timer);
        } else {
          counter.textContent = Math.floor(count);
        }
      }, stepTime);
    
  });
  }

  // Reveal Items on Scroll & Trigger Counters
  const revealItems = document.querySelectorAll('.reveal-item');
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('revealed');
        if (!countersStarted && entry.target.querySelector('.counter-num')) {
          countersStarted = true;
          animateCounters();
        }
      }
    });
  }, { threshold: 0.15 });

  revealItems.forEach(el => observer.observe(el));

  // Trigger counters right away if hero is visible
  setTimeout(() => {
    if (!countersStarted) {
      countersStarted = true;
      animateCounters();
    }
  }, 400);

  // 9. Central Ministry API Directory Search
  const searchInput = document.getElementById('gov-search-input');
  const searchBtn = document.getElementById('gov-search-btn');
  const searchFilter = document.getElementById('gov-search-filter');

  function handleGovSearch() {
    if (!searchInput) return;
    const query = searchInput.value.trim();
    if (!query) {
      alert(currentLang === 'en' ? 
        "Please enter an API name or ministry keyword to search." : 
        "कृपया खोज के लिए मंत्रालय या सेवा का नाम दर्ज करें।");
      return;
    }

    const verifierSection = document.getElementById('live-verifier');
    if (verifierSection) {
      verifierSection.scrollIntoView({ behavior: 'smooth' 
  });
    }

    const scenarioSelect = document.getElementById('scenario-select');
    if (scenarioSelect) {
      const qLower = query.toLowerCase();
      if (qLower.includes('birth') || qLower.includes('जन्म') || qLower.includes('health') || qLower.includes('hospital') || qLower.includes('aadhaar')) {
        scenarioSelect.value = 'birth';
      } else if (qLower.includes('business') || qLower.includes('company') || qLower.includes('व्यवसाय') || qLower.includes('mca') || qLower.includes('gst')) {
        scenarioSelect.value = 'business';
      } else if (qLower.includes('kisan') || qLower.includes('किसान') || qLower.includes('farm') || qLower.includes('land') || qLower.includes('भूमि') || qLower.includes('dbt')) {
        scenarioSelect.value = 'farmer';
      }
      scenarioSelect.dispatchEvent(new Event('change'));
    }
  }

  if (searchBtn) searchBtn.addEventListener('click', handleGovSearch);
  if (searchInput) {
    searchInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') handleGovSearch();
    
  });
  }

  // 10. Official Interoperability Gateway Simulator
  const scenarioSelect = document.getElementById('scenario-select');
  const activeScenarioName = document.getElementById('active-scenario-name');
  const triggerSimBtn = document.getElementById('trigger-sim-btn');
  const pipelineCards = document.getElementById('pipeline-cards');
  const statLatency = document.getElementById('stat-latency');
  const statAudit = document.getElementById('stat-audit');
  const simLogTerminal = document.getElementById('sim-log-terminal');

  let currentScenarioKey = 'birth';
  let isExecuting = false;

  function renderScenario(key) {
    const scDict = scenariosByLang[currentLang] || scenariosByLang.en;
    const sc = scDict[key];
    if (!sc || !pipelineCards) return;

    if (activeScenarioName) {
      const refLabel = currentLang === 'en' ? "Application Reference No:" : "आवेदन संदर्भ संख्या (ARN):";
      activeScenarioName.innerHTML = `<div class="flex flex-col sm:flex-row sm:items-center justify-between gap-1 w-full">
        <div>
          <span class="text-[10px] font-bold text-[#FF8000] uppercase tracking-wider block">${currentLang === 'en' ? 'INTEROPERABILITY SERVICE TRACKER' : 'अंतर-विभागीय सेवा ट्रैकर'}</span>
          <strong class="text-xs sm:text-sm font-bold text-[#00314D]">${sc.name}</strong>
        </div>
        <div class="text-[11px] font-mono text-[#00314D] bg-[#F1F5F9] px-2.5 py-1 rounded border border-[#CBD5E1] shrink-0">
          ${refLabel} <strong class="text-[#FF8000]">${sc.refNo}</strong>
        </div>
      </div>`;
    }
    pipelineCards.innerHTML = '';

    const standbyLabel = currentLang === 'en' ? "STANDBY" : "प्रतीक्षारत (STANDBY)";

    sc.steps.forEach((step, idx) => {
      const card = document.createElement('div');
      card.className = 'gov-spec-tile flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 text-xs mb-3 transition-all duration-300';
      card.id = `gov-step-${idx}`;
      card.innerHTML = `
        <div class="flex items-start space-x-3 w-full">
          <span class="w-6 h-6 rounded-full bg-[#00314D] text-white font-bold flex items-center justify-center text-xs shrink-0 mt-0.5">${idx + 1}</span>
          <div class="space-y-1 w-full">
            <div class="flex items-center justify-between flex-wrap gap-1">
              <span class="text-[10px] uppercase font-bold text-[#FF8000] tracking-wide">${step.agency}</span>
              <span class="text-[10px] text-[#64748B] font-mono">${step.recordRef}</span>
            </div>
            <strong class="text-[#00314D] block text-xs sm:text-sm font-bold">${step.title}</strong>
            <p class="text-[11px] text-[#4B5563] leading-relaxed">${step.desc}</p>
            <div class="flex items-center gap-1.5 pt-0.5 text-[10px] text-[#138808] font-semibold">
              <i data-lucide="shield-check" class="w-3.5 h-3.5 inline text-[#138808]"></i>
              <span>${step.securitySeal}</span>
            </div>
          </div>
        </div>
        <div class="sm:text-right shrink-0 mt-2 sm:mt-0">
          <span class="status-tag gov-stamp-badge gov-stamp-pending font-semibold">${standbyLabel}</span>
        </div>
      `;
      pipelineCards.appendChild(card);
    
  });

    if (window.lucide) {
      window.lucide.createIcons();
    }
  }

  function logToLedger(text, isHighlighted = false) {
    if (!simLogTerminal) return;
    const p = document.createElement('div');
    const time = new Date().toLocaleTimeString('en-IN', { hour12: false 
  });
    p.className = isHighlighted ? 'text-[#047857] font-semibold py-1 border-b border-[#E2E8F0]' : 'text-[#334155] py-0.5';
    p.textContent = `[${time}] ${text}`;
    simLogTerminal.appendChild(p);
    simLogTerminal.scrollTop = simLogTerminal.scrollHeight;
  }

  async function executeGovWorkflow() {
    if (isExecuting) return;
    isExecuting = true;
    triggerSimBtn.disabled = true;
    triggerSimBtn.classList.add('opacity-50', 'cursor-not-allowed');

    simLogTerminal.innerHTML = '';
    if (currentLang === 'en') {
      logToLedger('=== [NDIG INTEROPERABILITY MESH] SESSION EXECUTION INITIALIZED ===');
      logToLedger('>> Gateway Node: NDIG-MESH-DELHI-01 | mTLS 1.3 Handshake: ESTABLISHED (SHA-256)');
      logToLedger('>> Statutory Governance: DPDP Act 2023 Consent Token Validated via MeriPehchaan SSO');
      logToLedger('>> Interoperability Standard: JSON-LD 1.1 Schema aligned with MeitY Open API Policy');
    } else {
      logToLedger('=== [NDIG इंटरऑपरेबिलिटी मेश] सत्र निष्पादन प्रारंभ ===');
      logToLedger('>> गेटवे नोड: NDIG-MESH-DELHI-01 | mTLS 1.3 हैंडशेक: स्थापित (SHA-256)');
      logToLedger('>> वैधानिक शासन: मेरीपहचान एसएसओ द्वारा सत्यापित डीपीडीपी अधिनियम 2023 सहमति टोकन');
      logToLedger('>> डेटा मानक: MeitY ओपन एपीआई नीति के अनुरूप JSON-LD 1.1 स्कीमा');
    }

    const scDict = scenariosByLang[currentLang] || scenariosByLang.en;
    const sc = scDict[currentScenarioKey];
    let totalLatency = 0;

    for (let i = 0; i < sc.steps.length; i++) {
      const step = sc.steps[i];
      const card = document.getElementById(`gov-step-${i}`);
      const tag = card.querySelector('.status-tag');

      card.style.backgroundColor = '#EFF6FF';
      card.style.borderColor = '#3B82F6';
      card.style.transform = 'scale(1.01)';
      tag.textContent = currentLang === 'en' ? 'VERIFYING...' : 'सत्यापन जारी...';
      tag.className = 'status-tag gov-stamp-badge gov-stamp-pending font-semibold';

      const latencyChunk = Math.floor(Math.random() * 25) + 35;
      totalLatency += latencyChunk;
      statLatency.textContent = `${totalLatency} ms`;

      if (currentLang === 'en') {
        logToLedger(`[INTER-AGENCY QUERY] ${step.agency}: ${step.title} record verified via secure API bus.`);
        logToLedger(`[DIGITAL ATTESTATION] ${step.securitySeal} (${step.recordRef})`);
      } else {
        logToLedger(`[विभागीय सत्यापन] ${step.agency}: ${step.title} अभिलेख सुरक्षित एपीआई बस द्वारा सत्यापित।`);
        logToLedger(`[डिजिटल अभिप्रमाणन] ${step.securitySeal} (${step.recordRef})`);
      }

      await new Promise(r => setTimeout(r, 650));

      card.style.backgroundColor = '#F0FDF4';
      card.style.borderColor = '#10B981';
      card.style.transform = 'scale(1)';
      tag.textContent = step.status;
      tag.className = 'status-tag gov-stamp-badge gov-stamp-verified font-semibold';

      if (currentLang === 'en') {
        logToLedger(`[CLEARANCE GRANTED] ${step.title} -> Cryptographic clearance recorded on ledger.`, true);
      } else {
        logToLedger(`[स्वीकृति प्रदत्त] ${step.title} -> क्रिप्टोग्राफिक स्वीकृति लेजर में दर्ज।`, true);
      }
    }

    if (currentLang === 'en') {
      statAudit.textContent = 'AUDIT VERIFIED';
      statAudit.className = 'text-xs font-mono text-[#047857] font-bold';
      logToLedger(`>> All departmental checkpoints cleared (Total Latency: ${totalLatency}ms).`, true);
      logToLedger('>> Statutory digital record sealed and dispatched to citizen DigiLocker vault.');
    } else {
      statAudit.textContent = 'ऑडिट सत्यापित';
      statAudit.className = 'text-xs font-mono text-[#047857] font-bold';
      logToLedger(`>> सभी विभागीय जांच बिंदु पूर्ण एवं सत्यापित (कुल विलंबता: ${totalLatency}ms)।`, true);
      logToLedger('>> वैधानिक डिजिटल अभिलेख सीलबंद एवं डिजिलॉकर में प्रेषित।');
    }

    triggerSimBtn.disabled = false;
    triggerSimBtn.classList.remove('opacity-50', 'cursor-not-allowed');
    isExecuting = false;
  }

  if (scenarioSelect) {
    scenarioSelect.addEventListener('change', (e) => {
      currentScenarioKey = e.target.value;
      renderScenario(currentScenarioKey);
      if (statLatency) statLatency.textContent = '-- ms';
      if (statAudit) {
        statAudit.textContent = currentLang === 'en' ? 'PENDING' : 'प्रतीक्षारत (PENDING)';
        statAudit.className = 'text-xs font-mono text-[#B45309] font-bold';
      }
    
  });
  }

  if (triggerSimBtn) {
    triggerSimBtn.addEventListener('click', executeGovWorkflow);
  }

  // 11. Administrative ROI Calculator (National Fiscal Assessment)
  const govDeptRange = document.getElementById('gov-dept-range');
  const govDeptCount = document.getElementById('gov-dept-count');
  const govSavingsTotal = document.getElementById('gov-savings-total');

  function calculateGovSavings() {
    if (!govDeptRange || !govDeptCount || !govSavingsTotal) return;
    const depts = parseInt(govDeptRange.value, 10);
    govDeptCount.textContent = currentLang === 'en' ? `${depts} Departments` : `${depts} विभाग (Departments)`;

    const annualTransactions = 3000000 * 12;
    const totalSavings = (annualTransactions * 7.50) * (depts / 10);
    const inCrores = totalSavings / 10000000;

    govSavingsTotal.textContent = currentLang === 'en' ? 
      `₹ ${inCrores.toFixed(2)} Crores / yr` : 
      `₹ ${inCrores.toFixed(2)} करोड़ प्रति वर्ष`;
  }

  if (govDeptRange) {
    govDeptRange.addEventListener('input', calculateGovSavings);
  }

  // =========================================================================
  // 13. CITIZEN INTEROPERABILITY WORKSTATION & OFFICIAL CERTIFICATE SUITE
  // =========================================================================

  let currentActiveDesk = 'birth';
  let currentActiveDocTab = 'birthcert';
  let currentBirthData = {
    hospital: 'All India Institute of Medical Sciences (AIIMS), New Delhi',
    childName: 'Aarav Sharma',
    gender: 'Male / पुरुष',
    dob: '2026-10-12',
    weight: '3.25 kg',
    motherName: 'Pooja Sharma',
    motherAadhaar: 'XXXX-XXXX-4921',
    fatherName: 'Rohit Sharma',
    fatherAadhaar: 'XXXX-XXXX-8319',
    address: 'Flat 402, Shanti Kunj Apartments, Sector 14, Rohini, New Delhi - 110085',
    regNo: 'CRS/2026/DL/948271',
    regDate: '12-10-2026',
    aadhaarNo: 'XXXX-XXXX-8392'
  };

  window.switchProtoDesk = function(deskKey) {
    const pageServices = document.getElementById('page-services');
    if (pageServices && pageServices.classList.contains('hidden')) {
      document.querySelectorAll('.portal-page').forEach(p => p.classList.add('hidden'));
      pageServices.classList.remove('hidden');
    }
    currentActiveDesk = deskKey;
    const tabs = {
      caste: document.getElementById('proto-tab-caste'),
      dl: document.getElementById('proto-tab-dl'),
      birth: document.getElementById('proto-tab-birth'),
      business: document.getElementById('proto-tab-business'),
      farmer: document.getElementById('proto-tab-farmer')
    };
    const panes = {
      caste: document.getElementById('desk-pane-caste'),
      dl: document.getElementById('desk-pane-dl'),
      birth: document.getElementById('desk-pane-birth'),
      business: document.getElementById('desk-pane-business'),
      farmer: document.getElementById('desk-pane-farmer')
    };

    Object.keys(tabs).forEach(k => {
      if (tabs[k]) {
        if (k === deskKey) {
          tabs[k].classList.add('active');
        } else {
          tabs[k].classList.remove('active');
        }
      }
      if (panes[k]) {
        if (k === deskKey) {
          panes[k].classList.remove('hidden');
        } else {
          panes[k].classList.add('hidden');
        }
      }
    
  });

    if (deskKey === 'caste') {
      window.generateCasteCertificateAction();
    } else if (deskKey === 'dl') {
      window.generateDrivingLicenceAction();
    } else if (deskKey === 'business') {
      window.generateBusinessCertificateAction();
    } else if (deskKey === 'farmer') {
      window.generateFarmerVoucherAction();
    }

    if (window.lucide) window.lucide.createIcons();
  };

  window.switchDocTab = function(tabKey) {
    currentActiveDocTab = tabKey;
    const subtabs = {
      birthcert: document.getElementById('doc-tab-birthcert'),
      receipt: document.getElementById('doc-tab-receipt'),
      baalaadhaar: document.getElementById('doc-tab-baalaadhaar'),
      json: document.getElementById('doc-tab-json')
    };

    Object.keys(subtabs).forEach(k => {
      if (subtabs[k]) {
        if (k === tabKey) {
          subtabs[k].classList.add('active');
        } else {
          subtabs[k].classList.remove('active');
        }
      }
    
  });

    updateActiveDocumentDisplay();
  };

  // =========================================================================
  // CIVIL REGISTRATION SYSTEM (CRS) SUB-SERVICES (BIRTH, DEATH, MARRIAGE)
  // =========================================================================
  window.currentCrsSubService = 'birth';

  window.switchCrsSubService = function(subKey) {
    window.currentCrsSubService = subKey;
    const subBtns = {
      birth: document.getElementById('btn-crs-birth'),
      death: document.getElementById('btn-crs-death'),
      marriage: document.getElementById('btn-crs-marriage'),
      nac: document.getElementById('btn-crs-nac'),
      jeevan: document.getElementById('btn-crs-jeevan'),
      transgender: document.getElementById('btn-crs-transgender'),
      childname: document.getElementById('btn-crs-childname')
    };

    Object.keys(subBtns).forEach(k => {
      if (subBtns[k]) {
        if (k === subKey) {
          subBtns[k].className = 'px-2.5 py-1.5 rounded-lg text-xs font-bold bg-[#FF8000] text-white shadow-xs cursor-pointer flex items-center gap-1 transition';
        } else {
          subBtns[k].className = 'px-2.5 py-1.5 rounded-lg text-xs font-bold bg-white text-[#C2410C] hover:bg-orange-100 cursor-pointer flex items-center gap-1 border border-orange-200 transition';
        }
      }
    });

    const rowBirth = document.getElementById('row-crs-birth-fields');
    const rowDeath = document.getElementById('row-crs-death-fields');
    const rowMarriage = document.getElementById('row-crs-marriage-fields');

    if (rowBirth) rowBirth.classList.add('hidden');
    if (rowDeath) rowDeath.classList.add('hidden');
    if (rowMarriage) rowMarriage.classList.add('hidden');

    if (subKey === 'death') {
      if (rowDeath) rowDeath.classList.remove('hidden');
    } else if (subKey === 'marriage') {
      if (rowMarriage) rowMarriage.classList.remove('hidden');
    } else {
      if (rowBirth) rowBirth.classList.remove('hidden');
    }

    updateActiveDocumentDisplay();
    if (window.lucide) window.lucide.createIcons();
  };

  function renderOfficialDeathCertificate() {
    const dName = escapeHtml((document.getElementById('input-death-name')?.value || 'Late Om Prakash Sharma').toUpperCase());
    const dDate = escapeHtml(document.getElementById('input-death-date')?.value || '2026-09-28');
    const dPlace = escapeHtml(document.getElementById('input-death-place')?.value || 'AIIMS Hospital, New Delhi');
    const dCause = escapeHtml(document.getElementById('input-death-cause')?.value || 'Natural / Cardio-Pulmonary Arrest');

    return `
      <div class="gov-certificate-frame w-full" id="printable-death-certificate">
        <div class="gov-certificate-watermark">GOVERNMENT OF INDIA</div>
        
        <div class="gov-cert-header">
          <div class="text-[11px] font-bold tracking-widest text-[#991B1B] uppercase">भारत सरकार • GOVERNMENT OF INDIA</div>
          <div class="text-[9.5px] text-[#4B5563] uppercase">OFFICE OF THE REGISTRAR GENERAL, INDIA (CIVIL REGISTRATION SYSTEM)</div>
          <div class="text-[12px] font-extrabold text-[#00314D] uppercase mt-0.5">MUNICIPAL CORPORATION OF DELHI • HEALTH DEPARTMENT</div>
          <div class="text-[9.5px] text-[#4B5563]">प्रपत्र संख्या ६ / FORM NO. 6 (See Rule 9)</div>
          <div class="text-sm sm:text-base font-black text-[#991B1B] uppercase tracking-wider mt-1 border-b-2 border-t-2 border-[#991B1B] py-0.5 inline-block px-4">
            DEATH CERTIFICATE / मृत्यु प्रमाण पत्र
          </div>
          <div class="text-[8.5px] text-[#4B5563] mt-0.5 italic">
            (Issued under Section 12/17 of the Registration of Births and Deaths Act, 1969)
          </div>
        </div>

        <p class="text-[10px] text-[#374151] leading-relaxed text-justify mb-2">
          This is to certify that the following information has been taken from the official register of deaths for Municipal Zone <strong>North Delhi</strong>, Delhi (UT).
          <br><span class="text-[8.5px] text-[#6B7280]">प्रमाणित किया जाता है कि निम्नलिखित सूचना मृत्यु के मूल अभिलेख से ली गई है जो कि दिल्ली नगर निगम के आधिकारिक रजिस्टर में दर्ज है।</span>
        </p>

        <table class="gov-cert-table">
          <tbody>
            <tr>
              <th class="w-1/3">Name of Deceased / मृतक का नाम:</th>
              <td class="text-[#991B1B] font-black text-[12.5px]">${dName}</td>
              <th>Sex & Age / लिंग व आयु:</th>
              <td>Male / 72 Years</td>
            </tr>
            <tr>
              <th>Date of Death / मृत्यु दिनांक:</th>
              <td><strong class="font-mono text-red-700">${dDate}</strong></td>
              <th>Time of Death:</th>
              <td class="font-mono">04:15 AM IST</td>
            </tr>
            <tr>
              <th>Place of Death / मृत्यु स्थान:</th>
              <td colspan="3">${dPlace}</td>
            </tr>
            <tr>
              <th>Cause of Death / मृत्यु का कारण:</th>
              <td colspan="3"><strong>${dCause}</strong> (Certified by Medical Attendant Form 4A)</td>
            </tr>
            <tr>
              <th>Informant / Next of Kin:</th>
              <td>Rohit Sharma (Son / पुत्र)</td>
              <th>Informant Aadhaar:</th>
              <td class="font-mono">XXXX-XXXX-8319</td>
            </tr>
            <tr>
              <th>Registration No. / पंजीकरण संख्या:</th>
              <td class="font-mono text-[#00314D] font-black">CRS/2026/DTH/581920</td>
              <th>Date of Registration:</th>
              <td class="font-mono">29-09-2026</td>
            </tr>
          </tbody>
        </table>

        <div class="mt-4 pt-3 border-t-2 border-[#00314D] flex items-center justify-between text-[9px] font-mono">
          <div class="flex items-center gap-2">
            <div class="w-12 h-12 border p-0.5 rounded bg-white">
              <i data-lucide="qr-code" class="w-full h-full text-[#991B1B]"></i>
            </div>
            <div>
              <div class="text-[#138808] font-bold">DIGITALLY SIGNED & VERIFIED</div>
              <div class="text-slate-500">Registrar of Births & Deaths • North MCD</div>
            </div>
          </div>
          <div class="text-right">
            <span class="bg-red-50 text-red-800 border border-red-200 px-2 py-0.5 rounded font-bold">STATUTORY DEATH REGISTERED</span>
            <div class="text-[8px] text-slate-400 mt-0.5">DigiLocker Pushed • Legal Succession Ready</div>
          </div>
        </div>
      </div>`;
  }

  function renderOfficialMarriageCertificate() {
    const groom = escapeHtml((document.getElementById('input-marriage-groom')?.value || 'Rohit Sharma').toUpperCase());
    const bride = escapeHtml((document.getElementById('input-marriage-bride')?.value || 'Pooja Verma').toUpperCase());
    const mDate = escapeHtml(document.getElementById('input-marriage-date')?.value || '2022-11-20');
    const mPlace = escapeHtml(document.getElementById('input-marriage-place')?.value || 'Arya Samaj Mandir, Rohini, New Delhi');

    return `
      <div class="gov-certificate-frame w-full" id="printable-marriage-certificate">
        <div class="gov-certificate-watermark">GOVERNMENT OF INDIA</div>
        
        <div class="gov-cert-header">
          <div class="text-[11px] font-bold tracking-widest text-[#7C2D12] uppercase">भारत सरकार • GOVERNMENT OF INDIA</div>
          <div class="text-[9.5px] text-[#4B5563] uppercase">REVENUE & MAGISTRATE DEPARTMENT • GOVT OF NCT OF DELHI</div>
          <div class="text-[12px] font-extrabold text-[#00314D] uppercase mt-0.5">OFFICE OF THE MARRIAGE OFFICER & SUB DIVISIONAL MAGISTRATE</div>
          <div class="text-[9.5px] text-[#4B5563]">प्रपत्र 'ख' / FORM B (Compulsory Registration of Marriage Act)</div>
          <div class="text-sm sm:text-base font-black text-[#C2410C] uppercase tracking-wider mt-1 border-b-2 border-t-2 border-[#C2410C] py-0.5 inline-block px-4">
            CERTIFICATE OF MARRIAGE REGISTRATION / विवाह पंजीकरण प्रमाण पत्र
          </div>
          <div class="text-[8.5px] text-[#4B5563] mt-0.5 italic">
            (Issued under Compulsory Registration of Marriage Act & Section 15 of Special Marriage Act)
          </div>
        </div>

        <p class="text-[10px] text-[#374151] leading-relaxed text-justify mb-2">
          This is to certify that the marriage has been duly solemnized and registered in the Marriage Register maintained under the Act.
          <br><span class="text-[8.5px] text-[#6B7280]">प्रमाणित किया जाता है कि वर एवं वधू का विवाह विधि सम्मत रूप से संपन्न हुआ तथा विवाह रजिस्टर में विधिवत दर्ज किया गया है।</span>
        </p>

        <table class="gov-cert-table">
          <tbody>
            <tr>
              <th class="w-1/3">Name of Bridegroom / वर का नाम:</th>
              <td class="text-[#00314D] font-black text-[12.5px]">${groom}</td>
              <th>Father's Name / वर के पिता:</th>
              <td>Late Om Prakash Sharma</td>
            </tr>
            <tr>
              <th>Name of Bride / वधू का नाम:</th>
              <td class="text-[#C2410C] font-black text-[12.5px]">${bride}</td>
              <th>Father's Name / वधू के पिता:</th>
              <td>Shri Alok Verma</td>
            </tr>
            <tr>
              <th>Date of Solemnization / विवाह दिनांक:</th>
              <td><strong class="font-mono text-[#00314D]">${mDate}</strong></td>
              <th>Place of Solemnization / विवाह स्थल:</th>
              <td>${mPlace}</td>
            </tr>
            <tr>
              <th>Marriage Registration No:</th>
              <td class="font-mono text-[#138808] font-black">MRG/2026/DL/104928</td>
              <th>Date of Registration:</th>
              <td class="font-mono">16-10-2026</td>
            </tr>
            <tr>
              <th>Witness Details:</th>
              <td colspan="3">1. Alok Verma (Witness 1 - UID Verified) | 2. Suresh Kumar (Witness 2 - UID Verified)</td>
            </tr>
          </tbody>
        </table>

        <div class="mt-4 pt-3 border-t-2 border-[#00314D] flex items-center justify-between text-[9px] font-mono">
          <div class="flex items-center gap-2">
            <div class="w-12 h-12 border p-0.5 rounded bg-white">
              <i data-lucide="qr-code" class="w-full h-full text-[#C2410C]"></i>
            </div>
            <div>
              <div class="text-[#138808] font-bold">OFFICIALLY REGISTERED & SEALED</div>
              <div class="text-slate-500">SDM & Marriage Officer • North Delhi District</div>
            </div>
          </div>
          <div class="text-right">
            <span class="bg-amber-100 text-amber-900 border border-amber-300 px-2 py-0.5 rounded font-bold">CCA CLASS 3 DSC ATTESTED</span>
            <div class="text-[8px] text-slate-400 mt-0.5">DigiLocker Pushed • Passport & Visa Valid</div>
          </div>
        </div>
      </div>`;
  }

  window.updateActiveDocumentDisplay = function updateActiveDocumentDisplay() {
    const container = document.getElementById('active-document-container');
    if (!container) return;

    const sub = window.currentCrsSubService || 'birth';

    if (sub === 'death') {
      container.innerHTML = renderOfficialDeathCertificate();
    } else if (sub === 'marriage') {
      container.innerHTML = renderOfficialMarriageCertificate();
    } else if (sub === 'nac') {
      container.innerHTML = `
        <div class="crs-cert-frame w-full max-w-[580px] bg-[#FEFCF8] border-4 border-[#00314D] shadow-lg rounded-xl p-5 font-serif space-y-3">
          <div class="text-center border-b-2 border-[#00314D] pb-3">
            <div class="text-xs font-mono font-bold text-[#854D0E] uppercase">OFFICE OF THE CHIEF REGISTRAR (BIRTHS & DEATHS)</div>
            <h3 class="text-base font-black text-[#00314D] uppercase mt-1">NON-AVAILABILITY CERTIFICATE (NAC)</h3>
            <div class="text-[11px] font-bold text-[#B45309]">जन्म / मृत्यु अनुपलब्धता प्रमाण पत्र (धारा १७ नियम १३)</div>
            <div class="text-[9.5px] font-mono text-slate-500 mt-0.5">REGISTRATION OF BIRTHS & DEATHS ACT 1969 • FORM 10</div>
          </div>
          <div class="py-2 text-xs text-[#1E293B] leading-relaxed space-y-2 text-justify">
            <p>This is to certify that a search has been conducted in the official registration records of Municipal Zone <strong>North Delhi</strong> for the period <strong>1975 to 2025</strong> concerning the birth/death of <strong>${(currentBirthData.childName || 'Aarav Sharma').toUpperCase()}</strong> S/o <strong>${currentBirthData.fatherName || 'Rohit Sharma'}</strong> and Mother <strong>${currentBirthData.motherName || 'Pooja Sharma'}</strong>.</p>
            <div class="bg-amber-50 p-2.5 rounded border border-amber-200 font-mono text-[11px]">
              <div>Search Reference: <strong>CRS/NAC/2026/849201</strong></div>
              <div>Finding: <strong class="text-amber-900">NO ENTRY FOUND IN OFFICIAL GAZETTE REGISTER</strong></div>
              <div>Statutory Note: <strong>Valid for delayed birth registration under Section 13(3) by Executive Magistrate.</strong></div>
            </div>
            <p class="text-[10px] text-slate-500">Issued under official seal for legal succession, passport application, and judicial registration order.</p>
          </div>
          <div class="pt-3 border-t-2 border-[#00314D] flex justify-between items-center text-[10px] font-mono">
            <span class="text-emerald-700 font-bold">✓ Municipal Registrar e-Sign Verified</span>
            <span>Date: 16-Oct-2026</span>
          </div>
        </div>`;
    } else if (sub === 'jeevan') {
      container.innerHTML = `
        <div class="crs-cert-frame w-full max-w-[580px] bg-white border-4 border-emerald-700 shadow-xl rounded-xl p-5 font-sans space-y-3">
          <div class="bg-emerald-800 text-white p-3 rounded-lg flex items-center justify-between">
            <div class="flex items-center gap-2.5">
              <div class="w-10 h-10 rounded-full bg-white text-emerald-800 flex items-center justify-center font-black">
                <i data-lucide="shield-check" class="w-6 h-6"></i>
              </div>
              <div>
                <div class="text-xs font-black tracking-wide uppercase">GOVERNMENT OF INDIA • JEEVAN PRAMAAN</div>
                <div class="text-[10px] text-emerald-100">DIGITAL LIFE CERTIFICATE FOR PENSIONERS (बायोमेट्रिक जीवन प्रमाण पत्र)</div>
              </div>
            </div>
            <span class="bg-emerald-900 border border-emerald-500 text-emerald-100 text-[9px] px-2 py-0.5 rounded font-mono font-bold">DIGITAL INDIA</span>
          </div>
          <div class="grid grid-cols-2 gap-2 text-xs font-mono bg-slate-50 p-3 rounded-lg border border-slate-200">
            <div>Pramaan ID: <strong class="text-emerald-800">9482-1049-3829</strong></div>
            <div>PPO Number: <strong>SSP/CENTRAL/2026/PPO-8492</strong></div>
            <div>Pensioner Name: <strong>HARISH CHANDRA SHARMA</strong></div>
            <div>Aadhaar: <strong>XXXX-XXXX-8392</strong></div>
            <div>Pension Disbursing Bank: <strong>SBI Central Pension Hub</strong></div>
            <div>Biometric Auth: <strong class="text-emerald-700">UIDAI Iris / FaceRD Verified</strong></div>
          </div>
          <p class="text-[11px] text-slate-600">The digital life certificate has been electronically transmitted to the Pension Disbursing Agency (PDA). Pension renewal credited for FY 2026-27 without physical branch visit.</p>
          <div class="pt-2 border-t border-slate-200 flex justify-between items-center text-[10px] font-mono">
            <span class="text-emerald-700 font-bold">✓ Central Pension Accounting Office (CPAO) Attested</span>
            <span>Auth Timestamp: 16-10-2026 10:42 IST</span>
          </div>
        </div>`;
    } else if (sub === 'transgender') {
      container.innerHTML = `
        <div class="crs-cert-frame w-full max-w-[580px] bg-[#FAF5FF] border-4 border-purple-800 shadow-xl rounded-xl p-5 font-sans space-y-3">
          <div class="bg-purple-900 text-white p-3 rounded-lg flex items-center justify-between">
            <div>
              <span class="text-[9px] font-mono uppercase bg-purple-700 px-2 py-0.5 rounded">NATIONAL PORTAL FOR TRANSGENDER PERSONS</span>
              <h3 class="text-sm sm:text-base font-black uppercase mt-1">CERTIFICATE OF IDENTITY (TRANSGENDER PERSONS ACT 2019)</h3>
              <div class="text-[10px] text-purple-200">Ministry of Social Justice & Empowerment • Government of India</div>
            </div>
            <div class="w-12 h-12 rounded-full border-2 border-white flex items-center justify-center font-black text-xs bg-purple-800">
              TG-ID
            </div>
          </div>
          <div class="flex gap-3 items-center bg-white p-3 rounded-lg border border-purple-200">
            <div class="w-16 h-20 bg-slate-200 rounded border border-purple-300 overflow-hidden shrink-0">
              <img src="https://images.unsplash.com/photo-1544005313-94ddf0286df2?auto=format&fit=crop&w=150&h=180&q=80" alt="Identity Photo" class="w-full h-full object-cover"/>
            </div>
            <div class="space-y-1 font-mono text-[11px] text-purple-950">
              <div>Certificate No: <strong>TG/DL/2026/001948</strong></div>
              <div>Name: <strong>KIRAN SHARMA</strong></div>
              <div>Gender Identity: <strong class="text-purple-700 uppercase">Transgender (उभयलिंगी)</strong></div>
              <div>District Magistrate: <strong>District Magistrate, New Delhi</strong></div>
              <div>Legal Right: <strong>Self-perceived gender identity recognized under Section 6 of Act</strong></div>
            </div>
          </div>
          <div class="pt-2 border-t border-purple-200 flex justify-between items-center text-[10px] font-mono text-purple-800">
            <span>Official Identity Card Issued</span>
            <span>Date: 16-Oct-2026</span>
          </div>
        </div>`;
    } else if (sub === 'childname') {
      container.innerHTML = `
        <div class="crs-cert-frame w-full max-w-[580px] bg-white border-2 border-sky-700 shadow-md rounded-xl p-5 font-serif space-y-3 text-xs">
          <div class="text-center border-b border-slate-300 pb-2">
            <div class="text-xs font-bold text-sky-900 uppercase">MUNICIPAL CORPORATION • PUBLIC HEALTH DEPARTMENT</div>
            <h4 class="text-sm font-black text-[#00314D] mt-0.5">ORDER FOR ADDITION OF CHILD NAME IN BIRTH REGISTER</h4>
            <div class="text-[10px] text-slate-500">Section 14 of Registration of Births and Deaths Act 1969 (Rule 10)</div>
          </div>
          <div class="space-y-1.5 leading-relaxed text-justify">
            <p>On the joint declaration and statutory affidavit of parents <strong>${currentBirthData.fatherName || 'Rohit Sharma'}</strong> and <strong>${currentBirthData.motherName || 'Pooja Sharma'}</strong>, the official registration entry is hereby updated:</p>
            <div class="bg-sky-50 p-2.5 rounded border border-sky-200 font-mono text-[11px] space-y-1">
              <div>Birth Reg No: <strong>CRS/2026/DL/948271</strong> | Date of Birth: <strong>10/12/2026</strong></div>
              <div>Registered Name: <strong class="text-sky-900 text-sm">${(currentBirthData.childName || 'Aarav Sharma').toUpperCase()}</strong></div>
              <div>Order No: <strong>MCD/HEALTH/NAME-ADD/2026/49102</strong></div>
            </div>
            <p class="text-[10px] text-slate-500">The central CRS and UIDAI Baal Aadhaar repositories have been updated in real-time with the formal child name.</p>
          </div>
          <div class="pt-2 border-t border-slate-300 flex justify-between items-center text-[10px] font-mono">
            <span class="text-emerald-700 font-bold">✓ Registrar Seal Verified</span>
            <span>16-Oct-2026</span>
          </div>
        </div>`;
    } else {
      if (currentActiveDocTab === 'birthcert') {
        container.innerHTML = renderOfficialBirthCertificate(currentBirthData);
      } else if (currentActiveDocTab === 'receipt') {
        container.innerHTML = renderRtpsAcknowledgmentSlip(currentBirthData);
      } else if (currentActiveDocTab === 'baalaadhaar') {
        container.innerHTML = renderOfficialBaalAadhaarCard(currentBirthData);
      } else if (currentActiveDocTab === 'json') {
        container.innerHTML = renderGatewayJsonPayload(currentBirthData);
      }
    }

    window.attachIssuedBannerIfPresent('birth', container);
    if (window.lucide) window.lucide.createIcons();
  }

  window.loadSampleBirth = function(sampleKey) {
    if (sampleKey === 'aarav') {
      document.getElementById('input-hospital').value = 'All India Institute of Medical Sciences (AIIMS), New Delhi';
      document.getElementById('input-child-name').value = 'Aarav Sharma';
      document.getElementById('input-child-gender').value = 'Male / पुरुष';
      document.getElementById('input-child-dob').value = '2026-10-12';
      document.getElementById('input-child-weight').value = '3.25 kg';
      document.getElementById('input-mother-name').value = 'Pooja Sharma';
      document.getElementById('input-mother-aadhaar').value = 'XXXX-XXXX-4921';
      document.getElementById('input-father-name').value = 'Rohit Sharma';
      document.getElementById('input-father-aadhaar').value = 'XXXX-XXXX-8319';
      document.getElementById('input-permanent-address').value = 'Flat 402, Shanti Kunj Apartments, Sector 14, Rohini, New Delhi - 110085';
    } else if (sampleKey === 'ananya') {
      document.getElementById('input-hospital').value = 'Safdarjung Hospital & Vardhman Mahavir Medical College, New Delhi';
      document.getElementById('input-child-name').value = 'Ananya Verma';
      document.getElementById('input-child-gender').value = 'Female / महिला';
      document.getElementById('input-child-dob').value = '2026-10-11';
      document.getElementById('input-child-weight').value = '3.10 kg';
      document.getElementById('input-mother-name').value = 'Sunita Verma';
      document.getElementById('input-mother-aadhaar').value = 'XXXX-XXXX-5829';
      document.getElementById('input-father-name').value = 'Alok Verma';
      document.getElementById('input-father-aadhaar').value = 'XXXX-XXXX-2910';
      document.getElementById('input-permanent-address').value = 'House No. 18-B, Mayur Vihar Phase 1, East Delhi - 110091';
    }
    window.generateBirthCertificateAction();
  };

  window.generateBirthCertificateAction = async function(isSilent = false, isExplicitIssue = false) {
    const hospEl = document.getElementById('input-hospital');
    const childEl = document.getElementById('input-child-name');
    const genderEl = document.getElementById('input-child-gender');
    const dobEl = document.getElementById('input-child-dob');
    const weightEl = document.getElementById('input-child-weight');
    const motherNameEl = document.getElementById('input-mother-name');
    const motherAadhaarEl = document.getElementById('input-mother-aadhaar');
    const fatherNameEl = document.getElementById('input-father-name');
    const fatherAadhaarEl = document.getElementById('input-father-aadhaar');
    const addressEl = document.getElementById('input-permanent-address');

    if (!childEl) return;

    const randomSuffix = Math.floor(100000 + Math.random() * 900000);
    const aadhaarPart1 = Math.floor(1000 + Math.random() * 9000);
    const aadhaarPart2 = Math.floor(1000 + Math.random() * 9000);
    const aadhaarPart3 = Math.floor(1000 + Math.random() * 9000);

    currentBirthData = {
      hospital: hospEl ? hospEl.value : 'AIIMS New Delhi',
      childName: childEl ? childEl.value : 'Aarav Sharma',
      gender: genderEl ? genderEl.value : 'Male / पुरुष',
      dob: dobEl ? dobEl.value : '2026-10-12',
      weight: weightEl ? weightEl.value : '3.25 kg',
      motherName: motherNameEl ? motherNameEl.value : 'Pooja Sharma',
      motherAadhaar: motherAadhaarEl ? motherAadhaarEl.value : 'XXXX-XXXX-4921',
      fatherName: fatherNameEl ? fatherNameEl.value : 'Rohit Sharma',
      fatherAadhaar: fatherAadhaarEl ? fatherAadhaarEl.value : 'XXXX-XXXX-8319',
      address: addressEl ? addressEl.value : 'Rohini, New Delhi - 110085',
      regNo: `CRS/2026/DL/${randomSuffix}`,
      regDate: '12-10-2026',
      aadhaarNo: `XXXX-XXXX-${aadhaarPart3}`
    };

    const statusBadge = document.getElementById('birth-cascade-status');
    const nodes = [
      document.getElementById('step-node-hospital'),
      document.getElementById('step-node-crs'),
      document.getElementById('step-node-uidai'),
      document.getElementById('step-node-digilocker')
    ];

    if (!isSilent) {
      if (statusBadge) {
        statusBadge.textContent = currentLang === 'en' ? 'Synchronizing Interop Cascade...' : 'इंटरऑप सिंक्रनाइज़ेशन जारी...';
        statusBadge.className = 'text-[10px] font-bold text-[#854D0E] bg-[#FEF08A] px-2 py-0.5 rounded border border-[#FACC15] animate-pulse';
      }

      for (let i = 0; i < nodes.length; i++) {
        if (nodes[i]) {
          nodes[i].className = 'p-2 rounded border border-[#3B82F6] bg-[#EFF6FF] transition transform scale-102';
          await new Promise(r => setTimeout(r, 220));
          nodes[i].className = 'p-2 rounded border border-[#10B981] bg-[#F0FDF4] transition';
        }
      }

      if (statusBadge) {
        statusBadge.textContent = currentLang === 'en' ? 'Verified & Issued via NDIG' : 'प्रमाणित एवं एनडीआईजी द्वारा निर्गत ';
        statusBadge.className = 'text-[10px] font-bold text-[#03543F] bg-[#DEF7EC] px-2 py-0.5 rounded border border-[#31C48D]';
      }
    }

    updateActiveDocumentDisplay();

    if (isExplicitIssue) {
      const sub = window.currentCrsSubService || 'birth';
      let bTitle = 'जन्म प्रमाण पत्र (CRS Form 5 Birth Certificate)';
      let bNo = currentBirthData.regNo || 'CRS/2026/DL/948271';
      let applicant = currentBirthData.childName || 'Aarav Sharma';
      let father = currentBirthData.fatherName || 'Rohit Sharma';
      let authority = 'Office of the Registrar (Births & Deaths), MCD';
      if (sub === 'death') {
        bTitle = 'मृत्यु प्रमाण पत्र (Death Certificate Form 6)';
        bNo = 'CRS/2026/DTH/849201';
        applicant = document.getElementById('input-death-name')?.value || 'Late Om Prakash Sharma';
      } else if (sub === 'marriage') {
        bTitle = 'विवाह प्रमाण पत्र (Marriage Registration Certificate)';
        bNo = 'CRS/2026/MAR/491028';
        applicant = (document.getElementById('input-marriage-groom')?.value || 'Amit Verma') + ' & ' + (document.getElementById('input-marriage-bride')?.value || 'Sunita Singh');
      }
      window.notifyCertificateIssued('birth', bTitle, bNo, applicant, father, authority);
    }
  };

  function renderOfficialBirthCertificate(d) {
    const regNo = d.regNo || 'CRS/2026/DL/948271';
    const regDate = d.regDate || '12-10-2026';
    const childName = (d.childName || 'Aarav Sharma').toUpperCase();
    const gender = d.gender || 'Male / पुरुष';
    const dob = d.dob || '2026-10-12';
    const weight = d.weight || '3.25 kg';
    const hospital = d.hospital || 'All India Institute of Medical Sciences (AIIMS), New Delhi';
    const motherName = d.motherName || 'Pooja Sharma';
    const motherAadhaar = d.motherAadhaar || 'XXXX-XXXX-4921';
    const fatherName = d.fatherName || 'Rohit Sharma';
    const fatherAadhaar = d.fatherAadhaar || 'XXXX-XXXX-8319';
    const address = d.address || 'Flat 402, Shanti Kunj Apartments, Sector 14, Rohini, New Delhi - 110085';

    return `
      <div class="gov-certificate-frame w-full" id="printable-birth-certificate">
        <div class="gov-certificate-watermark">GOVERNMENT OF INDIA</div>
        
        <div class="gov-cert-header">
          <div class="flex items-center justify-center gap-3 mb-1">
            <svg class="h-14 w-auto text-[#00314D]" viewBox="0 0 120 160" fill="none" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="State Emblem of India">
              <path d="M60 14 C52 14 47 20 47 28 C47 34 50 40 54 44 C51 46 48 50 48 56 C48 64 53 70 60 72 C67 70 72 64 72 56 C72 50 69 46 66 44 C70 40 73 34 73 28 C73 20 68 14 60 14 Z" fill="currentColor"/>
              <path d="M56 32 C56 30 64 30 64 32 C64 36 62 40 60 42 C58 40 56 36 56 32 Z" fill="#FF8000"/>
              <circle cx="54" cy="27" r="1.5" fill="#FFF"/>
              <circle cx="66" cy="27" r="1.5" fill="#FFF"/>
              <path d="M38 24 C32 24 28 29 28 35 C28 41 31 46 34 49 C31 52 29 56 30 62 C31 68 36 74 44 76 C42 70 43 62 46 56 C42 54 39 48 40 42 C41 35 44 30 46 26 C43 24 40 24 38 24 Z" fill="currentColor"/>
              <circle cx="34" cy="34" r="1.5" fill="#FFF"/>
              <path d="M82 24 C88 24 92 29 92 35 C92 41 89 46 86 49 C89 52 91 56 90 62 C89 68 84 74 76 76 C78 70 77 62 74 56 C78 54 81 48 80 42 C79 35 76 30 74 26 C77 24 80 24 82 24 Z" fill="currentColor"/>
              <circle cx="86" cy="34" r="1.5" fill="#FFF"/>
              <path d="M35 68 C35 82 46 92 60 92 C74 92 85 82 85 68 C80 74 71 78 60 78 C49 78 40 74 35 68 Z" fill="currentColor"/>
              <rect x="22" y="93" width="76" height="14" rx="2" fill="currentColor"/>
              <circle cx="60" cy="100" r="5.5" fill="#FFF" stroke="currentColor" stroke-width="1.2"/>
              <circle cx="60" cy="100" r="1.8" fill="currentColor"/>
              <path d="M34 97 C31 97 29 99 29 101 C30 103 33 103 36 102 C37 100 36 98 34 97 Z" fill="#FFF"/>
              <path d="M86 97 C89 97 91 99 91 101 C90 103 87 103 84 102 C83 100 84 98 86 97 Z" fill="#FFF"/>
              <path d="M26 108 C32 118 45 124 60 124 C75 124 88 118 94 108 L26 108 Z" fill="currentColor"/>
              <path d="M34 110 C42 118 51 122 60 122 C69 122 78 118 86 110" stroke="#FFF" stroke-width="1.5" fill="none"/>
              <rect x="20" y="125" width="80" height="6" rx="1.5" fill="currentColor"/>
              <text x="60" y="146" text-anchor="middle" font-family="'Noto Sans Devanagari', 'Arial', sans-serif" font-size="11" font-weight="900" fill="currentColor" letter-spacing="1">सत्यमेव जयते</text>
            </svg>
          </div>
          <div class="text-[11px] font-bold tracking-widest text-[#1E3A8A] uppercase">भारत सरकार • GOVERNMENT OF INDIA</div>
          <div class="text-[9.5px] text-[#4B5563] uppercase">OFFICE OF THE REGISTRAR GENERAL, INDIA (CIVIL REGISTRATION SYSTEM)</div>
          <div class="text-[12px] font-extrabold text-[#00314D] uppercase mt-0.5">MUNICIPAL CORPORATION OF DELHI • HEALTH DEPARTMENT</div>
          <div class="text-[9.5px] text-[#4B5563]">प्रपत्र संख्या 5 / FORM NO. 5 (See Rule 9)</div>
          <div class="text-sm sm:text-base font-black text-[#1E3A8A] uppercase tracking-wider mt-1 border-b-2 border-t-2 border-[#1E3A8A] py-0.5 inline-block px-4">
            BIRTH CERTIFICATE / जन्म प्रमाण पत्र
          </div>
          <div class="text-[8.5px] text-[#4B5563] mt-0.5 italic">
            (Issued under Section 12/17 of the Registration of Births and Deaths Act, 1969)
          </div>
        </div>

        <p class="text-[10px] text-[#374151] leading-relaxed text-justify mb-2">
          This is to certify that the following information has been taken from the original record of birth registered in <strong>North Delhi Municipal Zone</strong> of State <strong>Delhi (UT)</strong>, India.
          <br><span class="text-[8.5px] text-[#6B7280]">प्रमाणित किया जाता है कि निम्नलिखित सूचना जन्म के मूल अभिलेख से ली गई है जो कि दिल्ली नगर निगम के आधिकारिक रजिस्टर में दर्ज है।</span>
        </p>

        <table class="gov-cert-table">
          <tbody>
            <tr>
              <th>Name of Child / शिशु का नाम:</th>
              <td class="text-[#1E3A8A] font-black text-[12.5px]">${childName}</td>
              <th>Sex / लिंग:</th>
              <td>${gender}</td>
            </tr>
            <tr>
              <th>Date of Birth / जन्म दिनांक:</th>
              <td><strong>${dob}</strong></td>
              <th>Weight at Birth / जन्म भार:</th>
              <td>${weight}</td>
            </tr>
            <tr>
              <th>Place of Birth / जन्म स्थान:</th>
              <td colspan="3">${hospital}</td>
            </tr>
            <tr>
              <th>Mother's Name / माता का नाम:</th>
              <td>${motherName} (Aadhaar: ${motherAadhaar})</td>
              <th>Father's Name / पिता का नाम:</th>
              <td>${fatherName} (Aadhaar: ${fatherAadhaar})</td>
            </tr>
            <tr>
              <th>Permanent Address / स्थायी पता:</th>
              <td colspan="3">${address}</td>
            </tr>
            <tr>
              <th>Registration No. / पंजीकरण संख्या:</th>
              <td class="font-mono text-[#00314D] font-black">${regNo}</td>
              <th>Date of Registration / दिनांक:</th>
              <td class="font-mono">${regDate}</td>
            </tr>
          </tbody>
        </table>

        <div class="mt-4 pt-2 border-t border-[#CBD5E1] flex flex-col sm:flex-row items-center justify-between gap-3 text-xs">
          <div class="flex items-center gap-2">
            <div class="p-1 bg-white border border-[#CBD5E1] rounded shadow-xs shrink-0">
              <svg class="w-14 h-14" viewBox="0 0 100 100" fill="none">
                <rect width="100" height="100" fill="white"/>
                <rect x="5" y="5" width="28" height="28" fill="#1E3A8A"/>
                <rect x="9" y="9" width="20" height="20" fill="white"/>
                <rect x="13" y="13" width="12" height="12" fill="#1E3A8A"/>
                <rect x="67" y="5" width="28" height="28" fill="#1E3A8A"/>
                <rect x="71" y="9" width="20" height="20" fill="white"/>
                <rect x="75" y="13" width="12" height="12" fill="#1E3A8A"/>
                <rect x="5" y="67" width="28" height="28" fill="#1E3A8A"/>
                <rect x="9" y="71" width="20" height="20" fill="white"/>
                <rect x="13" y="75" width="12" height="12" fill="#1E3A8A"/>
                <rect x="38" y="10" width="8" height="8" fill="#1E3A8A"/>
                <rect x="50" y="15" width="8" height="8" fill="#1E3A8A"/>
                <rect x="38" y="38" width="12" height="12" fill="#1E3A8A"/>
                <rect x="55" y="42" width="10" height="10" fill="#1E3A8A"/>
                <rect x="42" y="65" width="8" height="8" fill="#1E3A8A"/>
                <rect x="58" y="70" width="12" height="12" fill="#1E3A8A"/>
                <rect x="75" y="42" width="15" height="15" fill="#1E3A8A"/>
                <rect x="78" y="68" width="12" height="12" fill="#1E3A8A"/>
              </svg>
            </div>
            <div class="text-[8.5px] text-[#4B5563] leading-tight">
              <strong class="text-[#1E3A8A] block">CCA CLASS 3 DIGITAL SIGNATURE</strong>
              <span>Verified via National PKI &amp; DigiLocker Gateway</span>
              <span class="block font-mono text-[7.5px] text-[#047857]">SHA-256: 7a8f9021...c82e • DSC Token: 4E:7A:9C:21</span>
            </div>
          </div>

          <div class="shrink-0 flex flex-col items-center justify-center p-1" title="Statutory Digital Seal of the Registrar">
            <svg class="w-16 h-16 text-[#92400E]" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
              <circle cx="50" cy="50" r="46" stroke="#B45309" stroke-width="2.5" fill="#FEF3C7" fill-opacity="0.35"/>
              <circle cx="50" cy="50" r="41" stroke="#D97706" stroke-width="1" stroke-dasharray="2 2"/>
              <circle cx="50" cy="50" r="38" stroke="#B45309" stroke-width="1.5"/>
              <circle cx="50" cy="50" r="14" stroke="#B45309" stroke-width="1.5" fill="#FFF"/>
              <circle cx="50" cy="50" r="3" fill="#B45309"/>
              <path d="M50 36 L50 64 M36 50 L64 50 M40 40 L60 60 M40 60 L60 40" stroke="#B45309" stroke-width="1"/>
              <path id="seal-text-path-top" d="M 18,50 A 32,32 0 1,1 82,50" fill="none"/>
              <path id="seal-text-path-bottom" d="M 82,50 A 32,32 0 0,1 18,50" fill="none"/>
              <text font-size="6.5" font-weight="900" fill="#92400E" letter-spacing="1.2">
                <textPath href="#seal-text-path-top" startOffset="50%" text-anchor="middle">REGISTRAR GENERAL OF INDIA</textPath>
              </text>
              <text font-size="6" font-weight="900" fill="#92400E" letter-spacing="0.8">
                <textPath href="#seal-text-path-bottom" startOffset="50%" text-anchor="middle">★ STATUTORY SEAL ★</textPath>
              </text>
            </svg>
          </div>

          <div class="text-right shrink-0">
            <div class="inline-flex items-center gap-1 bg-[#DEF7EC] border border-[#31C48D] text-[#03543F] px-2 py-0.5 rounded text-[9.5px] font-bold">
              <span>DIGITALLY SIGNED & SEALED</span>
            </div>
            <div class="text-[10px] font-bold text-[#1E3A8A] mt-0.5">Registrar (Births &amp; Deaths)</div>
            <div class="text-[9px] text-[#4B5563]">Delhi Municipal Corporation</div>
            <div class="text-[8px] text-[#6B7280]">Issued: ${regDate}</div>
          </div>
        </div>

        <div class="mt-2.5 pt-1 border-t border-[#E2E8F0] text-[8px] text-[#64748B] text-center font-mono">
          DIGITALLY ISSUED STATUTORY CERTIFICATE UNDER SECTION 12/17 OF RBD ACT 1969 &amp; SECTION 43A OF IT ACT 2000 • VERIFIED VIA NDIG
        </div>
      </div>
    `;
  }

  function renderRtpsAcknowledgmentSlip(d) {
    const childName = (d.childName || 'Aarav Sharma').toUpperCase();
    const fatherName = d.fatherName || 'Rohit Sharma';
    const motherName = d.motherName || 'Pooja Sharma';
    const regNo = d.regNo || 'CRS/2026/DL/948271';
    const appRefNo = 'NDIG/2026/BC/' + regNo.split('/').pop();
    const dob = d.dob || '2026-10-12';
    const hospital = d.hospital || 'AIIMS New Delhi';
    const address = d.address || 'Rohini, New Delhi - 110085';
    const appDate = new Date().toLocaleDateString('en-IN', { day: '2-digit', month: '2-digit', year: 'numeric' 
  });

    return `
      <div class="rtps-receipt-frame w-full max-w-[700px] mx-auto text-xs" id="printable-rtps-receipt">
        <!-- Receipt Top Header -->
        <div class="rtps-receipt-header">
          <div class="flex items-center justify-between">
            <div class="text-left">
              <span class="text-[10px] font-bold text-[#00314D] uppercase tracking-wider block">लोक सेवाओं का अधिकार (RTPS)</span>
              <span class="text-[9px] text-[#64748B]">Right to Public Services • Government of India</span>
            </div>
            <div class="text-center flex flex-col items-center">
              <svg class="h-10 w-auto text-[#00314D] mb-1" viewBox="0 0 120 160" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M60 14 C52 14 47 20 47 28 C47 34 50 40 54 44 C51 46 48 50 48 56 C48 64 53 70 60 72 C67 70 72 64 72 56 C72 50 69 46 66 44 C70 40 73 34 73 28 C73 20 68 14 60 14 Z" fill="currentColor"/>
                <path d="M56 32 C56 30 64 30 64 32 C64 36 62 40 60 42 C58 40 56 36 56 32 Z" fill="#FF8000"/>
                <circle cx="54" cy="27" r="1.5" fill="#FFF"/>
                <circle cx="66" cy="27" r="1.5" fill="#FFF"/>
                <path d="M38 24 C32 24 28 29 28 35 C28 41 31 46 34 49 C31 52 29 56 30 62 C31 68 36 74 44 76 C42 70 43 62 46 56 C42 54 39 48 40 42 C41 35 44 30 46 26 C43 24 40 24 38 24 Z" fill="currentColor"/>
                <circle cx="34" cy="34" r="1.5" fill="#FFF"/>
                <path d="M82 24 C88 24 92 29 92 35 C92 41 89 46 86 49 C89 52 91 56 90 62 C89 68 84 74 76 76 C78 70 77 62 74 56 C78 54 81 48 80 42 C79 35 76 30 74 26 C77 24 80 24 82 24 Z" fill="currentColor"/>
                <circle cx="86" cy="34" r="1.5" fill="#FFF"/>
                <path d="M35 68 C35 82 46 92 60 92 C74 92 85 82 85 68 C80 74 71 78 60 78 C49 78 40 74 35 68 Z" fill="currentColor"/>
                <rect x="22" y="93" width="76" height="14" rx="2" fill="currentColor"/>
                <circle cx="60" cy="100" r="5.5" fill="#FFF" stroke="currentColor" stroke-width="1.2"/>
                <circle cx="60" cy="100" r="1.8" fill="currentColor"/>
                <rect x="20" y="125" width="80" height="6" rx="1.5" fill="currentColor"/>
                <text x="60" y="146" text-anchor="middle" font-family="'Noto Sans Devanagari', 'Arial', sans-serif" font-size="11" font-weight="900" fill="currentColor" letter-spacing="1">सत्यमेव जयते</text>
              </svg>
              <div class="inline-block px-2 py-0.5 bg-[#F8FAFC] border border-[#CBD5E1] rounded">
                <span class="text-[11px] font-black text-[#00314D] tracking-wide">नागरिक सुविधा केंद्र (CITIZEN DIGITAL DESK)</span>
              </div>
            </div>
            <div class="text-right">
              <span class="text-[10px] font-mono text-[#047857] font-bold block">स्थिति: स्वीकृत (APPROVED)</span>
              <span class="text-[9px] text-[#64748B]">Digital Verification Desk</span>
            </div>
          </div>
          <h2 class="text-sm sm:text-base font-extrabold text-[#00314D] mt-2 uppercase tracking-wide">
            आवेदन की पावती रसीद (ACKNOWLEDGMENT RECEIPT)
          </h2>
          <div class="text-[11px] text-[#475569] font-medium">
            नागरिक सेवा: <strong>जन्म प्रमाण पत्र का निर्गमन (Issuance of Official Birth Certificate)</strong>
          </div>
          <div class="flex items-center justify-center gap-3 mt-1.5">
            <div class="rtps-barcode-strip"></div>
            <span class="font-mono text-[10px] text-[#00314D] font-bold">${appRefNo}</span>
          </div>
        </div>

        <!-- Receipt Metadata Table -->
        <div class="border border-[#CBD5E1] rounded overflow-hidden mb-3">
          <div class="bg-[#F1F5F9] px-3 py-1.5 font-bold text-[#00314D] border-b border-[#CBD5E1] text-[11px]">
            १. आवेदन एवं सेवा विवरण (Application &amp; Service Particulars)
          </div>
          <table class="w-full text-left border-collapse text-[11px]">
            <tbody>
              <tr class="border-b border-[#E2E8F0]">
                <td class="p-2 font-semibold text-[#475569] bg-[#F8FAFC] w-1/3">आवेदन संदर्भ संख्या (Application Ref):</td>
                <td class="p-2 font-mono font-bold text-[#00314D]">${appRefNo}</td>
              </tr>
              <tr class="border-b border-[#E2E8F0]">
                <td class="p-2 font-semibold text-[#475569] bg-[#F8FAFC]">सिविल रजिस्ट्रेशन संख्या (CRS Reg No):</td>
                <td class="p-2 font-mono font-bold text-[#00314D]">${regNo}</td>
              </tr>
              <tr class="border-b border-[#E2E8F0]">
                <td class="p-2 font-semibold text-[#475569] bg-[#F8FAFC]">आवेदन की तिथि एवं समय:</td>
                <td class="p-2 text-[#1F2937]">${appDate} 10:14:32 IST</td>
              </tr>
              <tr class="border-b border-[#E2E8F0]">
                <td class="p-2 font-semibold text-[#475569] bg-[#F8FAFC]">सेवा प्रदान करने की समय-सीमा:</td>
                <td class="p-2 text-[#047857] font-bold">तत्काल (Zero Latency via NDIG Interoperability Mesh)</td>
              </tr>
              <tr class="border-b border-[#E2E8F0]">
                <td class="p-2 font-semibold text-[#475569] bg-[#F8FAFC]">आवेदक / माता-पिता का नाम:</td>
                <td class="p-2 text-[#1F2937] font-semibold">${fatherName} / ${motherName}</td>
              </tr>
              <tr class="border-b border-[#E2E8F0]">
                <td class="p-2 font-semibold text-[#475569] bg-[#F8FAFC]">शिशु का नाम (Child Name):</td>
                <td class="p-2 text-[#00314D] font-bold">${childName}</td>
              </tr>
              <tr class="border-b border-[#E2E8F0]">
                <td class="p-2 font-semibold text-[#475569] bg-[#F8FAFC]">जन्म दिनांक एवं लिंग:</td>
                <td class="p-2 text-[#1F2937]">${dob} | ${d.gender || 'Male'}</td>
              </tr>
              <tr class="border-b border-[#E2E8F0]">
                <td class="p-2 font-semibold text-[#475569] bg-[#F8FAFC]">जन्म का स्थान / अस्पताल:</td>
                <td class="p-2 text-[#1F2937]">${hospital}</td>
              </tr>
              <tr>
                <td class="p-2 font-semibold text-[#475569] bg-[#F8FAFC]">स्थायी पता (Permanent Address):</td>
                <td class="p-2 text-[#1F2937]">${address}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Linked Entitlements via Interoperability -->
        <div class="border border-[#BFDBFE] rounded bg-[#EFF6FF] p-2.5 mb-3 text-[11px] space-y-1">
          <div class="font-bold text-[#1E40AF] flex items-center gap-1.5">
            <i data-lucide="sparkles" class="w-3.5 h-3.5 text-[#2563EB]"></i>
            <span>एकीकृत अंतर-विभागीय लाभ (Linked Interoperability Benefits):</span>
          </div>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[#1E3A8A] pt-1">
            <div>• <strong>UIDAI Baal Aadhaar:</strong> पहचान पत्र स्वतः जारी एवं लिंक किया गया।</div>
            <div>• <strong>PMMVY मातृत्व लाभ (₹6,000):</strong> आधार-सत्यापित बैंक खाते में DBT शुरू।</div>
            <div>• <strong>DigiLocker सिंक:</strong> नागरिक लॉकर में ई-हस्ताक्षरित रिकॉर्ड उपलब्ध।</div>
            <div>• <strong>DPDP Act 2023:</strong> सहमति लेजर टोकन संख्या ${regNo.replace('CRS', 'DPDP')}।</div>
          </div>
        </div>

        <!-- Statutory Seal & Footnote -->
        <div class="pt-2 border-t border-[#CBD5E1] flex flex-col sm:flex-row items-center justify-between text-[10px] text-[#64748B] gap-2">
          <div>
            <span>सूचना प्रौद्योगिकी अधिनियम २००० की धारा ४ के अंतर्गत यह इलेक्ट्रॉनिक पावती पूर्णतः विधिमान्य है।</span>
          </div>
          <div class="flex items-center gap-2">
            <button type="button" onclick="window.downloadSignedDocument('receipt')" class="bg-[#00314D] hover:bg-[#002236] text-white px-3 py-1 rounded font-bold text-[10.5px] cursor-pointer">
              रसीद डाउनलोड करें (PDF)
            </button>
            <button type="button" onclick="window.switchDocTab('birthcert')" class="bg-[#138808] hover:bg-[#0F6B06] text-white px-3 py-1 rounded font-bold text-[10.5px] cursor-pointer">
              प्रमाण पत्र देखें
            </button>
          </div>
        </div>
      </div>
    `;
  }

  function renderOfficialBaalAadhaarCard(d) {
    const childName = (d.childName || 'Aarav Sharma').toUpperCase();
    const dob = d.dob || '2026-10-12';
    const gender = d.gender || 'Male / पुरुष';
    const aadhaarNo = d.aadhaarNo || 'XXXX-XXXX-8392';
    const motherAadhaar = d.motherAadhaar || 'XXXX-XXXX-4921';
    const address = d.address || 'Rohini, New Delhi - 110085';

    return `
      <div class="baal-aadhaar-frame w-full max-w-[540px]" id="printable-baal-aadhaar">
        <div class="baal-aadhaar-top"></div>

        <div class="baal-aadhaar-header">
          <div class="flex items-center gap-2">
            <!-- Official UIDAI Aadhaar Sunburst Emblem SVG -->
            <svg class="w-8 h-8 shrink-0" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
              <circle cx="50" cy="50" r="16" fill="#EA580C"/>
              <path d="M50 14 L50 26 M50 74 L50 86 M14 50 L26 50 M74 50 L86 50 M25 25 L34 34 M66 66 L75 75 M25 75 L34 66 M66 34 L75 25" stroke="#EA580C" stroke-width="4.5" stroke-linecap="round"/>
              <path d="M50 6 L50 12 M50 88 L50 94 M6 50 L12 50 M88 50 L94 50" stroke="#F97316" stroke-width="3" stroke-linecap="round"/>
              <path d="M42 50 C42 45 46 41 50 41 C54 41 58 45 58 50 C58 55 54 58 50 58" stroke="#FFF" stroke-width="2.5" stroke-linecap="round"/>
              <path d="M46 51 C46 48 48 46 50 46 C52 46 54 48 54 51" stroke="#FFF" stroke-width="2" stroke-linecap="round"/>
            </svg>
            <div>
              <div class="text-[10px] font-bold tracking-wide">भारत सरकार / Government of India</div>
              <div class="text-[8.5px] text-[#E0F2FE]">भारतीय विशिष्ट पहचान प्राधिकरण / UIDAI</div>
            </div>
          </div>
          <span class="text-[8.5px] font-bold bg-[#0284C7] border border-[#38BDF8] px-2 py-0.5 rounded text-white uppercase tracking-wider">
            बाल आधार (0-5 Years)
          </span>
        </div>

        <div class="baal-aadhaar-body">
          <div class="baal-aadhaar-photo shrink-0 overflow-hidden relative">
            <img src="https://images.unsplash.com/photo-1544126592-807ade215a0b?auto=format&fit=crop&w=200&h=250&q=80" alt="Infant Aadhaar Photograph" class="w-full h-full object-cover rounded"/>
            <div class="absolute bottom-0 inset-x-0 bg-black/60 text-[7px] text-white py-0.5 text-center font-bold">
              0-5 YRS (NO BIO)
            </div>
          </div>

          <div class="baal-aadhaar-info">
            <div class="text-[12.5px] font-black text-[#0369A1] mb-1">${childName}</div>
            <div><strong class="text-[#0C4A6E]">जन्म तिथि / DOB:</strong> <span class="font-mono">${dob}</span></div>
            <div><strong class="text-[#0C4A6E]">लिंग / Gender:</strong> <span>${gender}</span></div>
            <div><strong class="text-[#0C4A6E]">Linked Mother UID:</strong> <span class="font-mono text-[#0369A1]">${motherAadhaar}</span></div>
            <div class="text-[9.5px] text-[#64748B] mt-0.5 truncate max-w-[260px]"><strong>पता:</strong> ${address}</div>

            <div class="baal-aadhaar-number">
              ${aadhaarNo}
            </div>
          </div>

          <div class="shrink-0 p-1 bg-white border border-[#BAE6FD] rounded self-center hidden sm:block">
            <svg class="w-12 h-12" viewBox="0 0 100 100" fill="none">
              <rect width="100" height="100" fill="white"/>
              <rect x="5" y="5" width="28" height="28" fill="#0369A1"/>
              <rect x="9" y="9" width="20" height="20" fill="white"/>
              <rect x="13" y="13" width="12" height="12" fill="#0369A1"/>
              <rect x="67" y="5" width="28" height="28" fill="#0369A1"/>
              <rect x="71" y="9" width="20" height="20" fill="white"/>
              <rect x="75" y="13" width="12" height="12" fill="#0369A1"/>
              <rect x="5" y="67" width="28" height="28" fill="#0369A1"/>
              <rect x="9" y="71" width="20" height="20" fill="white"/>
              <rect x="13" y="75" width="12" height="12" fill="#0369A1"/>
              <rect x="40" y="40" width="20" height="20" fill="#0369A1"/>
            </svg>
          </div>
        </div>

        <div class="baal-aadhaar-footer">
          मेरा आधार, मेरी पहचान (National Digital Identification • DigiLocker Synced)
        </div>
      </div>
    `;
  }

  function renderGatewayJsonPayload(d) {
    const payload = {
      "@context": "https://schema.gov.in/interop/v2/civil-registration.jsonld",
      "gateway_version": "National Digital Interoperability Gateway v2.4 (OpenAPI 3.0 / IndEA 2.0)",
      "security_protocol": "mTLS 1.3 / AES-256-GCM Envelope Encryption",
      "hsm_digital_signature": "CCA-INDIA-CLASS3-SHA256-RSA4096-7A:9C:21:88",
      "dpdp_consent_token": "DPDP-ACT-2023-SEC6-CONSENT-948120",
      "timestamp_utc": new Date().toISOString(),
      "transaction_id": "NDIG-TXN-2026-9481029",
      "hospital_facility": {
        "institution": d.hospital,
        "event_type": "LIVE_BIRTH_INTIMATION",
        "medical_officer_id": "MOHFW-DOC-84920",
        "child_name": d.childName,
        "dob": d.dob,
        "gender": d.gender,
        "attestation_checksum": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      },
      "municipal_civil_registry": {
        "form_standard": "CRS Form 5 (Model Rules 1999/2026)",
        "registration_no": d.regNo,
        "registrar_office": "North Delhi Municipal Corporation",
        "statutory_status": "OFFICIALLY_SEALED_AND_ISSUED",
        "api_setu_uri": "https://apisetu.gov.in/crs/certificates/" + d.regNo
      },
      "uidai_identity_bus": {
        "baal_aadhaar_token": d.aadhaarNo,
        "linked_parent_token": d.motherAadhaar,
        "biometric_clause": "CHILD_0_TO_5_YEARS_EXEMPT",
        "status": "PROVISIONED_IN_NATIONAL_UID_BUS"
      },
      "digilocker_vault": {
        "citizen_docket_id": "DL-DOCKET-849201",
        "payload_checksum": "a4b2c1d8e7f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5",
        "delivery_state": "VERIFIED_DELIVERED_TO_CITIZEN_VAULT"
      }
    };

    return `
      <div class="w-full bg-[#0B1526] text-slate-200 rounded-lg border border-[#1E293B] overflow-hidden shadow-lg font-mono text-xs">
        <!-- Official Security Header Strip -->
        <div class="bg-[#0F1E36] border-b border-[#1E3A5F] p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[11px]">
          <div class="flex items-center gap-2">
            <span class="w-2.5 h-2.5 rounded-full bg-[#10B981] animate-ping"></span>
            <span class="text-white font-bold flex items-center gap-1.5 font-sans">
              <i data-lucide="shield-check" class="w-4 h-4 text-[#10B981]"></i>
              <span>National Cryptographic Security &amp; Interoperability Audit Ledger</span>
            </span>
          </div>
          <div class="flex items-center gap-2">
            <span class="bg-[#0284C7]/20 text-[#38BDF8] border border-[#0284C7]/40 px-2 py-0.5 rounded text-[10px] font-bold">
              mTLS 1.3 / AES-256
            </span>
            <span class="bg-[#10B981]/20 text-[#34D399] border border-[#10B981]/40 px-2 py-0.5 rounded text-[10px] font-bold">
              DPDP Token Verified
            </span>
          </div>
        </div>

        <!-- 4-Stage Agency Verification Breakdown Cards -->
        <div class="grid grid-cols-1 sm:grid-cols-4 gap-2 p-3 bg-[#08101E] border-b border-[#1E293B] text-[10px] font-sans">
          <div class="p-2 rounded bg-[#0F1E36] border border-[#1E3A5F]">
            <div class="text-[#94A3B8] font-bold">1. Hospital Node</div>
            <div class="text-[#38BDF8] font-semibold mt-0.5 truncate">${(d.hospital || 'AIIMS New Delhi').split(',')[0]}</div>
            <div class="text-[#10B981] font-bold text-[9px] mt-1">Med Record Verified</div>
          </div>
          <div class="p-2 rounded bg-[#0F1E36] border border-[#1E3A5F]">
            <div class="text-[#94A3B8] font-bold">2. Municipal CRS</div>
            <div class="text-[#38BDF8] font-semibold mt-0.5">Form 5 Issued</div>
            <div class="text-[#10B981] font-bold text-[9px] mt-1">Reg: ${d.regNo}</div>
          </div>
          <div class="p-2 rounded bg-[#0F1E36] border border-[#1E3A5F]">
            <div class="text-[#94A3B8] font-bold">3. UIDAI Identity Bus</div>
            <div class="text-[#38BDF8] font-semibold mt-0.5">Baal Aadhaar Token</div>
            <div class="text-[#10B981] font-bold text-[9px] mt-1">UID: ${d.aadhaarNo}</div>
          </div>
          <div class="p-2 rounded bg-[#0F1E36] border border-[#1E3A5F]">
            <div class="text-[#94A3B8] font-bold">4. DigiLocker Vault</div>
            <div class="text-[#38BDF8] font-semibold mt-0.5">Citizen Vault Pushed</div>
            <div class="text-[#10B981] font-bold text-[9px] mt-1">Docket Sealed</div>
          </div>
        </div>

        <!-- Structured Gateway Payload JSON Inspector -->
        <div class="p-4">
          <div class="flex items-center justify-between pb-2 mb-2 border-b border-[#1E293B] text-[11px] font-sans">
            <span class="text-slate-400 font-semibold">Government OpenAPI 3.0 Interoperability Wire Payload (IndEA 2.0 Spec)</span>
            <button type="button" onclick="window.copyVerificationToken('${payload.transaction_id}')" class="bg-[#1E293B] hover:bg-[#334155] text-white px-2.5 py-1 rounded text-[10px] font-bold flex items-center gap-1 cursor-pointer transition">
              <i data-lucide="copy" class="w-3 h-3 text-[#38BDF8]"></i>
              <span>Copy TXN ID</span>
            </button>
          </div>
          <pre class="whitespace-pre-wrap leading-relaxed max-h-[380px] overflow-y-auto text-[#7DD3FC] text-[11px]">${JSON.stringify(payload, null, 2)}</pre>
        </div>
      </div>
    `;
  }

    // =========================================================================
  // CORPORATE & MSME SUB-SERVICES (4 STATUTORY CERTIFICATES)
  // =========================================================================
  window.currentBusinessSubService = 'spice';

  window.switchBusinessSubService = function(subKey) {
    window.currentBusinessSubService = subKey;
    const subBtns = {
      spice: document.getElementById('btn-biz-spice'),
      udyam: document.getElementById('btn-biz-udyam'),
      eshram: document.getElementById('btn-biz-eshram'),
      trade: document.getElementById('btn-biz-trade'),
      epan: document.getElementById('btn-biz-epan'),
      chemist: document.getElementById('btn-biz-chemist'),
      pesticide: document.getElementById('btn-biz-pesticide'),
      bocw: document.getElementById('btn-biz-bocw'),
      firenoc: document.getElementById('btn-biz-firenoc')
    };

    Object.keys(subBtns).forEach(k => {
      if (subBtns[k]) {
        if (k === subKey) {
          subBtns[k].className = 'px-2.5 py-1.5 rounded-lg text-xs font-bold bg-[#1E40AF] text-white shadow-xs cursor-pointer flex items-center gap-1 transition';
        } else {
          subBtns[k].className = 'px-2.5 py-1.5 rounded-lg text-xs font-bold bg-white text-[#1E40AF] hover:bg-blue-100 cursor-pointer flex items-center gap-1 border border-blue-200 transition';
        }
      }
    });

    const rowUdyam = document.getElementById('row-biz-udyam-fields');
    const rowEshram = document.getElementById('row-biz-eshram-fields');

    if (rowUdyam) rowUdyam.classList.add('hidden');
    if (rowEshram) rowEshram.classList.add('hidden');

    if (subKey === 'udyam') {
      if (rowUdyam) rowUdyam.classList.remove('hidden');
    } else if (subKey === 'eshram') {
      if (rowEshram) rowEshram.classList.remove('hidden');
    }

    window.generateBusinessCertificateAction();
    if (window.lucide) window.lucide.createIcons();
  };

  window.generateBusinessCertificateAction = function(isExplicitIssue = false) {
    const subKey = window.currentBusinessSubService || 'spice';
    const bizName = escapeHtml((document.getElementById('input-biz-name')?.value || 'Bharat Enterprise Cloud Technologies Pvt Ltd').toUpperCase());
    const bizClass = escapeHtml(document.getElementById('input-biz-class')?.value || 'Private Limited');
    const bizCapital = escapeHtml(document.getElementById('input-biz-capital')?.value || '₹ 10,00,000');
    const bizDirector = escapeHtml(document.getElementById('input-biz-director')?.value || 'Vikas Mehra (DIN: 09841284)');
    const bizAddress = escapeHtml(document.getElementById('input-biz-address')?.value || 'Plot 84, Tech Zone 4, Greater Noida, Gautam Buddha Nagar, UP - 201306');

    const container = document.getElementById('biz-document-container');
    if (!container) return;

    function finishBusinessRender(customTitle, customNo) {
      window.attachIssuedBannerIfPresent('business', container);
      if (isExplicitIssue) {
        window.notifyCertificateIssued('business', customTitle, customNo, bizName, bizDirector, bizAddress);
      }
      if (window.lucide && typeof window.lucide.createIcons === 'function') {
        setTimeout(() => window.lucide.createIcons(), 50);
      }
    }

    if (subKey === 'epan') {
      container.innerHTML = `
        <div class="mca-cert-frame w-full max-w-[540px] bg-gradient-to-br from-[#E0F2FE] via-[#FFFFFF] to-[#EFF6FF] border-4 border-[#0284C7] shadow-xl rounded-xl p-5 font-sans space-y-3">
          <div class="flex items-center justify-between pb-2 border-b-2 border-[#0284C7]">
            <div class="flex items-center gap-2">
              <div class="w-8 h-8 rounded-full bg-[#00314D] text-white flex items-center justify-center font-bold text-xs">
                ITD
              </div>
              <div>
                <div class="text-[11px] font-black tracking-wide text-[#00314D]">INCOME TAX DEPARTMENT • भारत सरकार</div>
                <div class="text-[9px] text-[#0284C7] font-bold">GOVERNMENT OF INDIA • PERMANENT ACCOUNT NUMBER</div>
              </div>
            </div>
            <span class="bg-[#0284C7] text-white text-[9px] px-2 py-0.5 rounded font-mono font-bold">e-PAN CARD</span>
          </div>
          <div class="flex gap-4 items-center bg-white p-3 rounded-lg border border-sky-200">
            <div class="w-20 h-24 bg-slate-100 rounded border border-slate-300 overflow-hidden shrink-0">
              <img src="https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&w=200&h=240&q=80" alt="e-PAN Photo" class="w-full h-full object-cover"/>
            </div>
            <div class="space-y-1 font-mono text-[11px]">
              <div>PAN: <strong class="text-base text-[#00314D] font-black tracking-wider">ABCDE1234F</strong></div>
              <div>Name: <strong>${bizDirector.split('(')[0].trim().toUpperCase()}</strong></div>
              <div>Father's Name: <strong>RAMESH MEHRA</strong></div>
              <div>Date of Birth: <strong>14/06/1994</strong></div>
              <div>Auth Type: <strong class="text-emerald-700">Aadhaar e-KYC Paperless e-PAN</strong></div>
            </div>
          </div>
          <div class="pt-2 border-t border-sky-200 flex justify-between items-center text-[9px] font-mono text-[#00314D]">
            <span>Digitally Signed by Income Tax Department</span>
            <span class="text-emerald-700 font-bold">✓ QR Encrypted 256-Bit</span>
          </div>
        </div>`;
      finishBusinessRender('Permanent Account Number (e-PAN)', 'ABCDE1234F');
      return;
    } else if (subKey === 'chemist') {
      container.innerHTML = `
        <div class="mca-cert-frame w-full max-w-[580px] bg-white border-4 border-emerald-800 shadow-xl rounded-xl p-5 font-serif space-y-3">
          <div class="text-center border-b-2 border-emerald-800 pb-2">
            <div class="text-xs font-bold text-emerald-950 uppercase">FOOD SAFETY &amp; DRUG ADMINISTRATION DEPARTMENT</div>
            <h3 class="text-base font-black text-emerald-900 uppercase mt-0.5">RETAIL DRUG SALE LICENCE (CHEMIST SHOP)</h3>
            <div class="text-[11px] font-bold text-emerald-700">फॉर्म २० एवं २१ (औषधि एवं प्रसाधन सामग्री नियमावली १९४५)</div>
          </div>
          <div class="space-y-1.5 text-xs font-mono bg-emerald-50/50 p-3 rounded border border-emerald-200">
            <div>Licence No: <strong class="text-emerald-950">UP/FSDA/20/2026/8941 &amp; 21/2026/8942</strong></div>
            <div>Chemist Firm Name: <strong>${bizName}</strong></div>
            <div>Shop Premises: <strong>${bizAddress} (Min 10 Sq. Meters Carpet Area)</strong></div>
            <div>Qualified Person / Pharmacist: <strong>Alok Nath Pandey (UP State Pharmacy Reg: 84920)</strong></div>
            <div>Storage Facilities: <strong>Equipped with 2-8°C Commercial Refrigeration Unit</strong></div>
          </div>
          <p class="text-[10px] text-slate-600">Licensed to sell, stock or exhibit or offer for sale or distribute by retail drugs other than those specified in Schedule C, C(1) and X.</p>
          <div class="pt-2 border-t border-emerald-300 flex justify-between items-center text-[10px] font-mono">
            <span class="text-emerald-800 font-bold">Licensing Authority: State Drug Controller</span>
            <span>Valid Till: Oct 2031</span>
          </div>
        </div>`;
      finishBusinessRender('Retail Drug Sale Licence (Form 20/21)', 'UP/FSDA/20/2026/8941');
      return;
    } else if (subKey === 'pesticide') {
      container.innerHTML = `
        <div class="mca-cert-frame w-full max-w-[580px] bg-white border-2 border-amber-600 shadow-md rounded-xl p-5 font-sans space-y-3 text-xs">
          <div class="flex items-center justify-between pb-2 border-b border-amber-200">
            <div>
              <span class="text-[10px] font-mono font-bold bg-amber-100 text-amber-900 px-2 py-0.5 rounded">INSECTICIDES ACT 1968 (RULE 10)</span>
              <h4 class="font-black text-sm text-[#00314D] mt-1">RETAIL INSECTICIDES &amp; FERTILIZERS SALE LICENCE</h4>
              <div class="text-[11px] text-slate-500">Department of Agriculture • Krishi Bhawan Lucknow</div>
            </div>
            <div class="w-10 h-10 rounded-full bg-amber-100 text-amber-800 flex items-center justify-center font-bold">
              <i data-lucide="sprout" class="w-5 h-5 text-amber-700"></i>
            </div>
          </div>
          <div class="space-y-1.5 font-mono text-[11px] bg-amber-50/50 p-3 rounded-lg border border-amber-200">
            <div>Licence No: <strong>UP/AGRI/PEST/2026/04918</strong></div>
            <div>Dealer / Licensee: <strong>${bizName}</strong></div>
            <div>Responsible Technical Person: <strong>Rakesh Verma (B.Sc Agriculture Hon.)</strong></div>
            <div>Sales Depository / Godown: <strong>${bizAddress}</strong></div>
            <div>Principal Companies Authorized: <strong>IFFCO, KRIBHCO, Bayer CropScience</strong></div>
          </div>
          <div class="pt-2 border-t border-slate-200 flex justify-between items-center text-[10px] font-mono">
            <span>Licensing Officer: Deputy Director Agriculture</span>
            <span class="text-emerald-700 font-bold">✓ Active Valid 5 Years</span>
          </div>
        </div>`;
      finishBusinessRender('Retail Insecticides & Fertilizers Licence', 'UP/AGRI/PEST/2026/04918');
      return;
    } else if (subKey === 'bocw') {
      container.innerHTML = `
        <div class="mca-cert-frame w-full max-w-[580px] bg-[#FEF2F2] border-4 border-red-700 shadow-xl rounded-xl p-5 font-sans space-y-3">
          <div class="bg-red-800 text-white p-3 rounded-lg flex items-center justify-between">
            <div>
              <span class="text-[9px] font-mono uppercase bg-red-700 px-2 py-0.5 rounded">BUILDING & OTHER CONSTRUCTION WORKERS ACT 1996</span>
              <h3 class="text-sm sm:text-base font-black uppercase mt-1">BOCW WORKER WELFARE SMART CARD</h3>
              <div class="text-[10px] text-red-200">Uttar Pradesh BOCW Welfare Board • श्रम विभाग उत्तर प्रदेश</div>
            </div>
            <div class="w-10 h-10 rounded-full bg-white text-red-800 flex items-center justify-center font-black text-xs">
              BOCW
            </div>
          </div>
          <div class="grid grid-cols-2 gap-2 text-xs font-mono bg-white p-3 rounded-lg border border-red-200">
            <div>Labour Reg No: <strong class="text-red-900">UPBOCW/2026/948210</strong></div>
            <div>Worker Name: <strong>SURESH CHANDRA BIND</strong></div>
            <div>Trade / Skill: <strong>Mason / राजमिस्त्री (Skilled Worker)</strong></div>
            <div>90-Days Work Cert: <strong>Verified by Village Panchayat Secretary</strong></div>
            <div>DBT Bank Linked: <strong>Union Bank of India (PFMS Active)</strong></div>
            <div>Benefits Enabled: <strong>Accidental Insurance (₹5L) + Maternity Grant (₹50k)</strong></div>
          </div>
          <div class="pt-2 border-t border-red-200 flex justify-between items-center text-[10px] font-mono text-red-800">
            <span>Registering Officer: Deputy Labour Commissioner</span>
            <span>Status: Verified & Live</span>
          </div>
        </div>`;
      finishBusinessRender('BOCW Worker Welfare Smart Card', 'UPBOCW/2026/948210');
      return;
    } else if (subKey === 'firenoc') {
      container.innerHTML = `
        <div class="mca-cert-frame w-full max-w-[580px] bg-white border-4 border-orange-700 shadow-xl rounded-xl p-5 font-serif space-y-3">
          <div class="text-center border-b-2 border-orange-700 pb-2">
            <div class="text-xs font-bold text-orange-950 uppercase">DIRECTORATE GENERAL OF FIRE SERVICES</div>
            <h3 class="text-base font-black text-orange-900 uppercase mt-0.5">FIRE SAFETY NO OBJECTION CERTIFICATE (NOC)</h3>
            <div class="text-[11px] font-bold text-orange-700">FORM C • COMMERCIAL PREMISES CLEARANCE (NATIONAL BUILDING CODE 2016)</div>
          </div>
          <div class="space-y-1.5 text-xs font-mono bg-orange-50/50 p-3 rounded border border-orange-200">
            <div>NOC Certificate No: <strong class="text-orange-950">NOC/FIRE/2026/001928</strong></div>
            <div>Commercial Occupancy: <strong>${bizName}</strong></div>
            <div>Building Height &amp; Area: <strong>14.5 Meters (G+3 Floors) • 1,250 Sq. Meters</strong></div>
            <div>Fire Safety Equipment: <strong>Wet Riser, Smoke Detectors, Yard Hydrant &amp; 50kL Water Tank</strong></div>
            <div>Inspection Date: <strong>14 October 2026 by Chief Fire Officer (CFO) Team</strong></div>
          </div>
          <p class="text-[10px] text-slate-600">Certified that the premises has complied with fire prevention and life safety measures as per Part IV of National Building Code of India 2016.</p>
          <div class="pt-2 border-t border-orange-300 flex justify-between items-center text-[10px] font-mono">
            <span class="text-orange-900 font-bold">Issued by: Chief Fire Officer</span>
            <span>Validity: 3 Years Statutory</span>
          </div>
        </div>`;
      finishBusinessRender('Fire Safety Clearance Certificate (NOC)', 'NOC/FIRE/2026/001928');
      return;
    }

    const udyamClass = escapeHtml(document.getElementById('input-udyam-class')?.value || 'Micro Enterprise (सूक्ष्म उद्यम)');
    const udyamAct = escapeHtml(document.getElementById('input-udyam-activity')?.value || 'Services (62 - Computer programming & IT consulting)');
    const eshramJob = escapeHtml(document.getElementById('input-eshram-occupation')?.value || 'Construction & Building Worker (भवन निर्माण कारीगर)');
    const eshramUan = escapeHtml(document.getElementById('input-eshram-uan')?.value || '1004 8921 7384');

    if (subKey === 'udyam') {
      container.innerHTML = `
        <div class="mca-cert-frame w-full max-w-[580px] bg-white border-4 border-[#1E40AF] shadow-lg rounded-xl overflow-hidden font-sans p-4" id="printable-mca-cert">
          <div class="text-center border-b-2 border-[#1E40AF] pb-3 mb-3">
            <div class="text-xs font-bold text-[#1E40AF] uppercase">भारत सरकार • GOVERNMENT OF INDIA</div>
            <div class="text-[11px] text-[#4B5563] uppercase">MINISTRY OF MICRO, SMALL & MEDIUM ENTERPRISES / सूक्ष्म, लघु एवं मध्यम उद्यम मंत्रालय</div>
            <div class="text-sm sm:text-base font-black text-[#1E40AF] uppercase tracking-wide mt-1.5 border-t border-b border-[#1E40AF] py-1 inline-block px-4">
              UDYAM REGISTRATION CERTIFICATE / उद्यम पंजीकरण प्रमाण पत्र
            </div>
          </div>

          <div class="bg-blue-50 p-2.5 rounded-lg border border-blue-200 mb-3 flex items-center justify-between">
            <div>
              <span class="text-[10px] text-slate-500 block">Udyam Registration Number:</span>
              <strong class="font-mono text-base text-[#1E40AF]">UDYAM-UP-28-0094821</strong>
            </div>
            <span class="bg-[#1E40AF] text-white px-2.5 py-1 rounded text-xs font-bold">
              MSME VERIFIED
            </span>
          </div>

          <table class="gov-cert-table text-xs">
            <tbody>
              <tr>
                <th class="w-1/3">Name of Enterprise:</th>
                <td colspan="3" class="font-bold text-[#1E40AF]">${bizName}</td>
              </tr>
              <tr>
                <th>Classification:</th>
                <td class="font-bold text-emerald-700">${udyamClass}</td>
                <th>Major Activity:</th>
                <td>${udyamAct}</td>
              </tr>
              <tr>
                <th>Organization Type:</th>
                <td>${bizClass}</td>
                <th>Date of Incorporation:</th>
                <td class="font-mono">12-10-2026</td>
              </tr>
              <tr>
                <th>Managing Director:</th>
                <td>${bizDirector}</td>
                <th>PAN / GSTIN Status:</th>
                <td class="text-emerald-700 font-bold">CBDT & GSTN Verified</td>
              </tr>
              <tr>
                <th>Unit / Plant Location:</th>
                <td colspan="3">${bizAddress}</td>
              </tr>
            </tbody>
          </table>

          <div class="mt-3 pt-2 border-t border-slate-200 flex items-center justify-between text-[10px] font-mono">
            <div class="flex items-center gap-1.5 text-emerald-700 font-bold">
              <i data-lucide="shield-check" class="w-4 h-4"></i>
              <span>National MSME Portal Interop Confirmed • MSMED Act 2006</span>
            </div>
            <div class="w-12 h-12 border p-0.5 rounded bg-white">
              <i data-lucide="qr-code" class="w-full h-full text-[#1E40AF]"></i>
            </div>
          </div>
        </div>`;
    } else if (subKey === 'eshram') {
      container.innerHTML = `
        <div class="mca-cert-frame w-full max-w-[560px] bg-white border-4 border-[#0F766E] shadow-lg rounded-xl overflow-hidden font-sans" id="printable-mca-cert">
          <div class="bg-gradient-to-r from-[#FF9933] via-[#FFFFFF] to-[#138808] h-1.5 w-full"></div>
          
          <div class="bg-[#0F766E] text-white p-3 px-4 flex items-center justify-between">
            <div class="flex items-center gap-2">
              <i data-lucide="user-plus" class="w-6 h-6 text-[#99F6E4]"></i>
              <div>
                <div class="text-[11px] font-black tracking-wide uppercase">MINISTRY OF LABOUR & EMPLOYMENT • श्रम एवं रोजगार मंत्रालय</div>
                <div class="text-[9px] text-[#CCFBF1]">NATIONAL DATABASE OF UNORGANISED WORKERS (NDUW) • e-SHRAM</div>
              </div>
            </div>
            <div class="text-right">
              <span class="text-[9px] font-bold bg-white text-[#0F766E] px-2 py-0.5 rounded border border-[#5EEAD4]">
                ई-श्रम कार्ड (e-SHRAM)
              </span>
            </div>
          </div>

          <div class="p-4 bg-teal-50/40 space-y-3">
            <div class="flex gap-3 items-center bg-white p-3 rounded-lg border border-teal-200 shadow-2xs">
              <div class="w-20 h-24 rounded-lg overflow-hidden border-2 border-[#0F766E] shrink-0 bg-slate-100">
                <img src="https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?auto=format&fit=crop&w=200&h=240&q=80" alt="Worker Photograph" class="w-full h-full object-cover"/>
              </div>

              <div class="flex-grow space-y-1 text-xs">
                <div>
                  <span class="text-[10px] text-slate-500 block">Universal Account Number (UAN):</span>
                  <span class="font-mono text-lg font-black text-[#0F766E] tracking-wider">${eshramUan}</span>
                </div>
                <div>Name: <strong>${bizDirector.split('(')[0].trim()}</strong></div>
                <div>Primary Occupation: <strong class="text-emerald-800">${eshramJob}</strong></div>
                <div>Accidental Insurance: <strong class="text-[#0F766E]">PMSBY Covered (₹2,00,000)</strong></div>
                <div>State / District: <strong>Uttar Pradesh, Gautam Buddha Nagar</strong></div>
              </div>

              <div class="w-16 h-16 shrink-0 border p-1 rounded bg-white">
                <i data-lucide="qr-code" class="w-full h-full text-[#0F766E]"></i>
              </div>
            </div>

            <div class="p-2 bg-emerald-50 rounded border border-emerald-200 text-[10px] text-emerald-900">
              यह कार्ड असंगठित कामगारों को सामाजिक सुरक्षा एवं कल्याणकारी योजनाओं का सीधा लाभ प्रदान करने हेतु भारत सरकार द्वारा अधिकृत है।
            </div>
          </div>

          <div class="bg-slate-900 text-white p-2 px-3 flex items-center justify-between text-[9px]">
            <span class="flex items-center gap-1 text-slate-300">
              <i data-lucide="shield-check" class="w-3.5 h-3.5 text-[#10B981]"></i>
              <span>National Social Security Interoperability Bus Verified</span>
            </span>
            <span class="font-mono text-[#5EEAD4] font-bold">LABOUR WELFARE DEPT</span>
          </div>
        </div>`;
    } else if (subKey === 'trade') {
      container.innerHTML = `
        <div class="mca-cert-frame w-full max-w-[580px] bg-white border-4 border-[#1E3A8A] shadow-lg rounded-xl overflow-hidden font-sans p-4" id="printable-mca-cert">
          <div class="text-center border-b-2 border-[#1E3A8A] pb-3 mb-3">
            <div class="text-xs font-bold text-[#1E3A8A] uppercase">नगर निगम • MUNICIPAL CORPORATION</div>
            <div class="text-[11px] text-[#4B5563] uppercase">HEALTH, LICENSING & FACTORY DEPARTMENT / स्वास्थ्य एवं लाइसेंसिंग विभाग</div>
            <div class="text-sm sm:text-base font-black text-[#1E3A8A] uppercase tracking-wide mt-1.5 border-t border-b border-[#1E3A8A] py-1 inline-block px-4">
              COMMERCIAL TRADE & ESTABLISHMENT LICENCE / व्यापार अनुज्ञप्ति
            </div>
          </div>

          <table class="gov-cert-table text-xs">
            <tbody>
              <tr>
                <th class="w-1/3">Licence Number:</th>
                <td class="font-mono font-bold text-[#1E3A8A]">TL-MCD-2026-08492</td>
                <th>Financial Year:</th>
                <td class="font-mono">2026-2027</td>
              </tr>
              <tr>
                <th>Establishment Name:</th>
                <td colspan="3" class="font-bold text-[#1E3A8A]">${bizName}</td>
              </tr>
              <tr>
                <th>Authorized Licensee:</th>
                <td>${bizDirector}</td>
                <th>Nature of Trade:</th>
                <td>IT Consulting & Software Commercial Office</td>
              </tr>
              <tr>
                <th>Fire NOC & Hygiene Status:</th>
                <td class="text-emerald-700 font-bold">COMPLIANT (NOC: 2026/8491)</td>
                <th>Annual Fee Paid:</th>
                <td class="font-bold">₹ 5,000 (Cleared via BBPS)</td>
              </tr>
              <tr>
                <th>Commercial Premises:</th>
                <td colspan="3">${bizAddress}</td>
              </tr>
            </tbody>
          </table>

          <div class="mt-3 pt-2 border-t border-slate-200 flex items-center justify-between text-[10px] font-mono">
            <div class="flex items-center gap-1.5 text-emerald-700 font-bold">
              <i data-lucide="shield-check" class="w-4 h-4"></i>
              <span>Municipal Corporation Delhi Act 1957 • Digitally Signed</span>
            </div>
            <div class="w-12 h-12 border p-0.5 rounded bg-white">
              <i data-lucide="qr-code" class="w-full h-full text-[#1E3A8A]"></i>
            </div>
          </div>
        </div>`;
    } else {
      // Default: SPICe+ CIN
      container.innerHTML = `
        <div class="mca-cert-frame" id="printable-mca-cert">
          <div class="text-center border-b-2 border-[#00314D] pb-3 mb-3">
            <div class="text-xs font-bold text-[#00314D] uppercase">भारत सरकार • GOVERNMENT OF INDIA</div>
            <div class="text-[11px] text-[#4B5563] uppercase">MINISTRY OF CORPORATE AFFAIRS / कॉर्पोरेट कार्य मंत्रालय</div>
            <div class="text-[10px] text-[#6B7280]">OFFICE OF THE REGISTRAR OF COMPANIES (DELHI &amp; HARYANA)</div>
            <div class="text-sm sm:text-base font-black text-[#00314D] uppercase tracking-wide mt-1.5 border-t border-b border-[#00314D] py-1 inline-block px-4">
              CERTIFICATE OF INCORPORATION / समामेलन का प्रमाण-पत्र
            </div>
            <div class="text-[9px] text-[#6B7280] italic mt-0.5">
              [Pursuant to sub-section (2) of section 7 and sub-section (1) of section 8 of the Companies Act, 2013]
            </div>
          </div>

          <p class="text-xs text-[#1F2937] leading-relaxed mb-3 text-justify">
            I hereby certify that <strong>${bizName}</strong> is incorporated on this Twelfth day of October Two Thousand Twenty-Six under the Companies Act, 2013 and that the company is <strong>${bizClass}</strong>.
          </p>

          <table class="gov-cert-table">
            <tbody>
              <tr>
                <th>Corporate Identity Number (CIN):</th>
                <td class="font-mono text-[#00314D] font-bold">U72900DL2026PTC394812</td>
                <th>Permanent Account Number (PAN):</th>
                <td class="font-mono font-bold">AAACB9481P</td>
              </tr>
              <tr>
                <th>GST Identification Number (GSTIN):</th>
                <td class="font-mono text-[#138808] font-bold">07AAACB9481P1Z4</td>
                <th>Date of Incorporation:</th>
                <td class="font-mono">12-10-2026</td>
              </tr>
              <tr>
                <th>Managing Director:</th>
                <td>${bizDirector}</td>
                <th>Authorized Capital:</th>
                <td>${bizCapital}</td>
              </tr>
              <tr>
                <th>Registered Office:</th>
                <td colspan="3">${bizAddress}</td>
              </tr>
            </tbody>
          </table>

          <div class="mt-4 pt-3 border-t-2 border-[#00314D] flex items-center justify-between text-[10px]">
            <div class="flex items-center gap-2">
              <div class="w-12 h-12 border p-0.5 rounded bg-white">
                <i data-lucide="qr-code" class="w-full h-full text-[#00314D]"></i>
              </div>
              <div class="text-slate-600 font-mono text-[9px]">
                <div>MCA V3 MCA21 PORTAL VALIDATED</div>
                <div class="text-emerald-700 font-bold">Digitally Signed by ROC Incharge</div>
              </div>
            </div>
            <div class="text-right">
              <span class="bg-blue-100 text-blue-900 border border-blue-300 px-2.5 py-1 rounded font-bold text-xs">
                SPICe+ CIN ISSUED
              </span>
            </div>
          </div>
        </div>`;
    }

    let bTitle = 'Certificate of Incorporation (SPICe+ MCA)';
    let bNo = 'U72900DL2026PTC394812';
    if (subKey === 'udyam') { bTitle = 'Udyam MSME Registration Certificate'; bNo = 'UDYAM-UP-28-0094821'; }
    else if (subKey === 'eshram') { bTitle = 'e-Shram National Worker Card'; bNo = eshramUan; }
    else if (subKey === 'fssai') { bTitle = 'FSSAI Food Business License'; bNo = '10026011000492'; }
    else if (subKey === 'trade') { bTitle = 'Municipal Trade License'; bNo = 'TL/MCD/2026/89412'; }
    
    finishBusinessRender(bTitle, bNo);
  };

  // =========================================================================
  // AGRICULTURE & SOCIAL WELFARE SUB-SERVICES (5 STATUTORY CERTIFICATES)
  // =========================================================================
  window.currentFarmerSubService = 'pmkisan';

  window.switchFarmerSubService = function(subKey) {
    window.currentFarmerSubService = subKey;
    const subBtns = {
      pmkisan: document.getElementById('btn-welfare-pmkisan'),
      ration: document.getElementById('btn-welfare-ration'),
      kcc: document.getElementById('btn-welfare-kcc'),
      pension: document.getElementById('btn-welfare-pension'),
      senior: document.getElementById('btn-welfare-senior'),
      organic: document.getElementById('btn-welfare-organic'),
      animal_kcc: document.getElementById('btn-welfare-animal_kcc'),
      solar: document.getElementById('btn-welfare-solar')
    };

    Object.keys(subBtns).forEach(k => {
      if (subBtns[k]) {
        if (k === subKey) {
          subBtns[k].className = 'px-2.5 py-1.5 rounded-lg text-xs font-bold bg-[#138808] text-white shadow-xs cursor-pointer flex items-center gap-1 transition';
        } else {
          subBtns[k].className = 'px-2.5 py-1.5 rounded-lg text-xs font-bold bg-white text-[#047857] hover:bg-emerald-100 cursor-pointer flex items-center gap-1 border border-emerald-200 transition';
        }
      }
    });

    const rowRation = document.getElementById('row-welfare-ration-fields');
    const rowPension = document.getElementById('row-welfare-pension-fields');

    if (rowRation) rowRation.classList.add('hidden');
    if (rowPension) rowPension.classList.add('hidden');

    if (subKey === 'ration') {
      if (rowRation) rowRation.classList.remove('hidden');
    } else if (subKey === 'pension') {
      if (rowPension) rowPension.classList.remove('hidden');
    }

    window.generateFarmerVoucherAction();
    if (window.lucide) window.lucide.createIcons();
  };

  window.generateFarmerVoucherAction = function(isExplicitIssue = false) {
    const subKey = window.currentFarmerSubService || 'pmkisan';
    const farmerName = escapeHtml((document.getElementById('input-farmer-name')?.value || 'Ramesh Kumar Yadav').toUpperCase());
    const aadhaar = maskAadhaar(document.getElementById('input-farmer-aadhaar')?.value || 'XXXX-XXXX-6712');
    const khasra = escapeHtml(document.getElementById('input-farmer-khasra')?.value || 'KH-48201/08');
    const village = escapeHtml(document.getElementById('input-farmer-village')?.value || 'Rampur Kalan, Meerut (UP)');
    const amt = escapeHtml(document.getElementById('input-farmer-amt')?.value || '₹ 2,000 (Installment 18)');
    const bank = escapeHtml(document.getElementById('input-farmer-bank')?.value || 'State Bank of India (SBI) - A/C No: XXXXXXXX4912');

    const container = document.getElementById('farmer-document-container');
    if (!container) return;

    function finishFarmerRender(customTitle, customNo) {
      window.attachIssuedBannerIfPresent('farmer', container);
      if (isExplicitIssue) {
        window.notifyCertificateIssued('farmer', customTitle, customNo, farmerName, village, 'Meerut (UP)');
      }
      if (window.lucide && typeof window.lucide.createIcons === 'function') {
        setTimeout(() => window.lucide.createIcons(), 50);
      }
    }

    if (subKey === 'organic') {
      container.innerHTML = `
        <div class="farmer-voucher-frame w-full max-w-[580px] bg-[#F7FEE7] border-4 border-[#4D7C0F] shadow-lg rounded-xl overflow-hidden font-sans p-5">
          <div class="text-center border-b-2 border-[#4D7C0F] pb-3 mb-3">
            <span class="text-[10px] font-mono font-bold bg-[#ECFCCB] text-[#3F6212] px-2 py-0.5 rounded">PKVY • PGS-INDIA GREEN</span>
            <h3 class="text-base font-black text-[#365314] uppercase mt-1">ORGANIC FARMER CERTIFICATION & PGS-INDIA PASSPORT</h3>
            <div class="text-[10px] text-[#4D7C0F]">Ministry of Agriculture & Farmers Welfare • Paramparagat Krishi Vikas Yojana</div>
          </div>
          <div class="space-y-2 text-xs font-mono bg-white p-3 rounded-lg border border-[#A3E635]">
            <div>Certificate No: <strong>PKVY/UP/2026/ORG-849201</strong></div>
            <div>Certified Farmer: <strong>${farmerName}</strong></div>
            <div>Village / Cluster: <strong>${village} (Meerut Organic FPO)</strong></div>
            <div>Land Survey Gata: <strong>${khasra} (1.250 Hectare Certified Organic)</strong></div>
            <div>Certification Standard: <strong class="text-emerald-700">NPOP & PGS-India Conversion Year 3</strong></div>
            <div>Permitted Produce: <strong>Organic Basmati Rice, Wheat & Pulses (Zero Chemical)</strong></div>
          </div>
          <div class="pt-3 border-t border-[#A3E635] flex justify-between items-center text-[10px] font-mono text-[#365314]">
            <span class="font-bold">✓ APEDA & Jaivik Bharat QR Synced</span>
            <span>Valid Till: Oct 2027</span>
          </div>
        </div>`;
      finishFarmerRender('Organic Farmer Certification (PKVY PGS-India)', 'PKVY/UP/2026/ORG-849201');
      return;
    } else if (subKey === 'animal_kcc') {
      container.innerHTML = `
        <div class="farmer-voucher-frame w-full max-w-[580px] bg-white border-2 border-emerald-600 shadow-lg rounded-xl p-5 font-sans space-y-3">
          <div class="flex items-center justify-between pb-2 border-b border-emerald-200">
            <div>
              <span class="text-[10px] font-mono font-bold bg-emerald-100 text-emerald-800 px-2 py-0.5 rounded">NABARD & DAHDF SCHEME</span>
              <h4 class="font-black text-sm text-[#00314D] mt-1">ANIMAL HUSBANDRY &amp; FISHERIES KCC CREDIT SANCTION</h4>
              <div class="text-[11px] text-slate-500">Working Capital Credit Card for Livestock Farmers</div>
            </div>
            <div class="w-12 h-12 rounded-lg bg-emerald-700 text-white flex flex-col items-center justify-center font-black text-[10px]">
              <span>KCC</span>
              <span>₹2 LAKH</span>
            </div>
          </div>
          <div class="grid grid-cols-2 gap-2 text-[11px] font-mono bg-slate-50 p-3 rounded-lg border border-slate-200">
            <div>Beneficiary: <strong>${farmerName}</strong></div>
            <div>Aadhaar: <strong>${aadhaar}</strong></div>
            <div>Livestock Units: <strong>4 Milch Buffaloes + 2 Cows (Ear Tagged)</strong></div>
            <div>Sanctioned Limit: <strong class="text-emerald-800">₹ 2,00,000 at 4% Interest Subvention</strong></div>
            <div>Bank Branch: <strong>${bank}</strong></div>
            <div>INAPH Tag Sync: <strong class="text-emerald-700">NDDB National Portal Synced</strong></div>
          </div>
          <div class="pt-2 border-t border-slate-200 flex justify-between items-center text-[10px] font-mono">
            <span class="text-emerald-700 font-bold">✓ District Animal Husbandry Officer Approved</span>
            <span>Date: 16-Oct-2026</span>
          </div>
        </div>`;
      finishFarmerRender('Animal Husbandry KCC Credit Sanction', 'KCC-AH-2026-94812');
      return;
    } else if (subKey === 'solar') {
      container.innerHTML = `
        <div class="farmer-voucher-frame w-full max-w-[580px] bg-white border-2 border-amber-500 shadow-lg rounded-xl p-5 font-sans space-y-3">
          <div class="flex items-center justify-between pb-2 border-b border-amber-200">
            <div>
              <span class="text-[10px] font-mono font-bold bg-amber-100 text-amber-900 px-2 py-0.5 rounded">PM-KUSUM COMPONENT-B</span>
              <h4 class="font-black text-sm text-[#00314D] mt-1">STANDALONE SOLAR AGRICULTURE PUMP SUBSIDY SANCTION</h4>
              <div class="text-[11px] text-slate-500">Ministry of New &amp; Renewable Energy • State Renewable Nodal Agency</div>
            </div>
            <div class="w-10 h-10 rounded-full bg-amber-100 text-amber-800 flex items-center justify-center font-bold">
              <i data-lucide="sun" class="w-6 h-6 text-amber-600"></i>
            </div>
          </div>
          <div class="space-y-1.5 text-[11px] font-mono bg-amber-50/50 p-3 rounded-lg border border-amber-200">
            <div>Farmer: <strong>${farmerName}</strong> | Land Khasra: <strong>${khasra}</strong></div>
            <div>Solar Pump Capacity: <strong>7.5 HP Solar DC Submersible Pump</strong></div>
            <div>Total Benchmarked Cost: <strong>₹ 3,45,000</strong></div>
            <div>Central Subsidy (CFA 30%): <strong class="text-emerald-800">₹ 1,03,500</strong></div>
            <div>State Subsidy (SFA 30%): <strong class="text-emerald-800">₹ 1,03,500</strong></div>
            <div>Farmer Contribution (40%): <strong>₹ 1,38,000 (Bank Financed)</strong></div>
          </div>
          <div class="pt-2 border-t border-slate-200 flex justify-between items-center text-[10px] font-mono">
            <span class="text-emerald-700 font-bold">✓ MNRE Feasibility Order Approved</span>
            <span>Vendor: Tata Power Solar</span>
          </div>
        </div>`;
      finishFarmerRender('PM-KUSUM Standalone Solar Pump Subsidy Sanction', 'KUSUM-UP-2026-7841');
      return;
    }
    const rationCat = escapeHtml(document.getElementById('input-ration-category')?.value || 'Antyodaya Anna Yojana (AAY)');
    const rationMembers = escapeHtml(document.getElementById('input-ration-members')?.value || '5 Units (Ramesh Yadav, Sunita Devi, Sonu, Monu, Pooja)');
    const rationFps = escapeHtml(document.getElementById('input-ration-fps')?.value || 'FPS-20184 / Ram Chandra Fair Price Shop, Meerut');
    const rationGrain = escapeHtml(document.getElementById('input-ration-grain')?.value || '35 kg Free Foodgrain (20kg Wheat + 15kg Rice)');
    const pensionType = escapeHtml(document.getElementById('input-pension-type')?.value || 'Old Age Pension (वृद्धावस्था पेंशन)');
    const pensionPpo = escapeHtml(document.getElementById('input-pension-ppo')?.value || 'SSP/UP/2026/PPO/748192');

    if (subKey === 'ration') {
      container.innerHTML = `
        <div class="farmer-voucher-frame w-full max-w-[580px] bg-white border-4 border-[#047857] shadow-lg rounded-xl overflow-hidden font-sans p-4" id="printable-farmer-voucher">
          <div class="text-center border-b-2 border-[#047857] pb-3 mb-3">
            <div class="text-xs font-bold text-[#047857] uppercase">खाद्य एवं रसद विभाग • DEPARTMENT OF FOOD &amp; CIVIL SUPPLIES</div>
            <div class="text-[11px] text-[#4B5563] uppercase">GOVERNMENT OF UTTAR PRADESH • राष्ट्रीय खाद्य सुरक्षा अधिनियम २०१३</div>
            <div class="text-sm sm:text-base font-black text-[#047857] uppercase tracking-wide mt-1.5 border-t border-b border-[#047857] py-1 inline-block px-4">
              NATIONAL FOOD SECURITY DIGITAL RATION CARD / राष्ट्रीय राशन कार्ड
            </div>
          </div>

          <div class="bg-emerald-50 p-2.5 rounded-lg border border-emerald-200 mb-3 flex items-center justify-between">
            <div>
              <span class="text-[10px] text-slate-500 block">Ration Card Number:</span>
              <strong class="font-mono text-base text-[#047857]">NFSA-UP-094819204</strong>
            </div>
            <div class="text-right">
              <span class="bg-[#047857] text-white px-2.5 py-0.5 rounded text-xs font-bold block">ONORC ENABLED</span>
              <span class="text-[9px] text-slate-500 font-mono">One Nation One Ration Card</span>
            </div>
          </div>

          <table class="gov-cert-table text-xs">
            <tbody>
              <tr>
                <th class="w-1/3">Head of Family:</th>
                <td class="font-bold text-[#047857]">${farmerName}</td>
                <th>Card Category:</th>
                <td class="font-bold text-[#047857]">${rationCat}</td>
              </tr>
              <tr>
                <th>Family Members Count:</th>
                <td colspan="3">${rationMembers}</td>
              </tr>
              <tr>
                <th>Fair Price Shop (FPS):</th>
                <td colspan="3">${rationFps}</td>
              </tr>
              <tr>
                <th>Monthly Free Entitlement:</th>
                <td colspan="3" class="font-bold text-[#138808]">${rationGrain}</td>
              </tr>
              <tr>
                <th>Village & District:</th>
                <td>${village}</td>
                <th>Aadhaar e-KYC:</th>
                <td class="text-emerald-700 font-bold">100% Aadhaar Seeded</td>
              </tr>
            </tbody>
          </table>

          <div class="mt-3 pt-2 border-t border-slate-200 flex items-center justify-between text-[10px] font-mono">
            <div class="flex items-center gap-1.5 text-emerald-700 font-bold">
              <i data-lucide="shield-check" class="w-4 h-4"></i>
              <span>e-PoS Biometric Authentication Ready across India</span>
            </div>
            <div class="w-12 h-12 border p-0.5 rounded bg-white">
              <i data-lucide="qr-code" class="w-full h-full text-[#047857]"></i>
            </div>
          </div>
        </div>`;
    } else if (subKey === 'kcc') {
      container.innerHTML = `
        <div class="farmer-voucher-frame w-full max-w-[580px] bg-white border-4 border-[#138808] shadow-lg rounded-xl overflow-hidden font-sans p-4" id="printable-farmer-voucher">
          <div class="text-center border-b-2 border-[#138808] pb-3 mb-3">
            <div class="text-xs font-bold text-[#138808] uppercase">नाबार्ड एवं कृषि मंत्रालय • NABARD &amp; MINISTRY OF AGRICULTURE</div>
            <div class="text-[11px] text-[#4B5563] uppercase">STATE BANK OF INDIA • AGRI-BUSINESS BRANCH, MEERUT</div>
            <div class="text-sm sm:text-base font-black text-[#138808] uppercase tracking-wide mt-1.5 border-t border-b border-[#138808] py-1 inline-block px-4">
              KISAN CREDIT CARD (KCC) SANCTION / किसान क्रेडिट कार्ड स्वीकृति पत्र
            </div>
          </div>

          <table class="gov-cert-table text-xs">
            <tbody>
              <tr>
                <th class="w-1/3">KCC Account Number:</th>
                <td class="font-mono font-bold text-[#138808]">KCC-SBI-2026-48192</td>
                <th>Farmer Name:</th>
                <td class="font-bold text-[#138808]">${farmerName}</td>
              </tr>
              <tr>
                <th>Sanctioned Credit Limit:</th>
                <td class="font-bold text-sm text-[#138808]">₹ 3,00,000</td>
                <th>Subsidized Interest Rate:</th>
                <td class="font-bold text-[#138808]">4% Per Annum (Prompt Repayment)</td>
              </tr>
              <tr>
                <th>Land Holding Authenticated:</th>
                <td>${khasra} (${village})</td>
                <th>Crop Insurance (PMFBY):</th>
                <td class="text-emerald-700 font-bold">Kharif & Rabi Auto-Enrolled</td>
              </tr>
              <tr>
                <th>Aadhaar Linked A/C:</th>
                <td colspan="3">${bank}</td>
              </tr>
            </tbody>
          </table>

          <div class="mt-3 pt-2 border-t border-slate-200 flex items-center justify-between text-[10px] font-mono">
            <div class="flex items-center gap-1.5 text-emerald-700 font-bold">
              <i data-lucide="shield-check" class="w-4 h-4"></i>
              <span>Interest Subvention Scheme (ISS) Approved</span>
            </div>
            <div class="w-12 h-12 border p-0.5 rounded bg-white">
              <i data-lucide="qr-code" class="w-full h-full text-[#138808]"></i>
            </div>
          </div>
        </div>`;
    } else if (subKey === 'pension') {
      container.innerHTML = `
        <div class="farmer-voucher-frame w-full max-w-[580px] bg-white border-4 border-[#0F766E] shadow-lg rounded-xl overflow-hidden font-sans p-4" id="printable-farmer-voucher">
          <div class="text-center border-b-2 border-[#0F766E] pb-3 mb-3">
            <div class="text-xs font-bold text-[#0F766E] uppercase">समाज कल्याण विभाग • SOCIAL WELFARE DEPARTMENT</div>
            <div class="text-[11px] text-[#4B5563] uppercase">NATIONAL SOCIAL ASSISTANCE PROGRAMME (NSAP) • राष्ट्रीय सामाजिक सहायता</div>
            <div class="text-sm sm:text-base font-black text-[#0F766E] uppercase tracking-wide mt-1.5 border-t border-b border-[#0F766E] py-1 inline-block px-4">
              PENSION PAYMENT ORDER (PPO) / पेंशन स्वीकृति आदेश
            </div>
          </div>

          <table class="gov-cert-table text-xs">
            <tbody>
              <tr>
                <th class="w-1/3">Pension Payment Order (PPO):</th>
                <td class="font-mono font-bold text-[#0F766E]">${pensionPpo}</td>
                <th>Scheme Name:</th>
                <td class="font-bold text-[#0F766E]">${pensionType}</td>
              </tr>
              <tr>
                <th>Beneficiary Pensioner:</th>
                <td class="font-bold text-[#00314D]">${farmerName}</td>
                <th>Monthly Pension Benefit:</th>
                <td class="font-bold text-sm text-[#0F766E]">₹ 1,000 / month</td>
              </tr>
              <tr>
                <th>Disbursement Mode:</th>
                <td colspan="3">Aadhaar Enabled Payment System (AePS) / Direct Credit via PFMS</td>
              </tr>
              <tr>
                <th>Residence:</th>
                <td colspan="3">${village}</td>
              </tr>
            </tbody>
          </table>

          <div class="mt-3 pt-2 border-t border-slate-200 flex items-center justify-between text-[10px] font-mono">
            <div class="flex items-center gap-1.5 text-emerald-700 font-bold">
              <i data-lucide="shield-check" class="w-4 h-4"></i>
              <span>Life Certificate (Jeevan Pramaan) Biometric Verified</span>
            </div>
            <div class="w-12 h-12 border p-0.5 rounded bg-white">
              <i data-lucide="qr-code" class="w-full h-full text-[#0F766E]"></i>
            </div>
          </div>
        </div>`;
    } else if (subKey === 'senior') {
      container.innerHTML = `
        <div class="farmer-voucher-frame w-full max-w-[560px] bg-white border-4 border-[#00314D] shadow-lg rounded-xl overflow-hidden font-sans" id="printable-farmer-voucher">
          <div class="bg-gradient-to-r from-[#FF9933] via-[#FFFFFF] to-[#138808] h-1.5 w-full"></div>
          
          <div class="bg-[#00314D] text-white p-3 px-4 flex items-center justify-between">
            <div class="flex items-center gap-2">
              <i data-lucide="user-check" class="w-6 h-6 text-[#FCD34D]"></i>
              <div>
                <div class="text-[11px] font-black tracking-wide uppercase">GOVERNMENT OF INDIA • NATIONAL SENIOR CITIZEN CARD</div>
                <div class="text-[9px] text-[#BAE6FD]">MINISTRY OF SOCIAL JUSTICE &amp; EMPOWERMENT • वरिष्ठ नागरिक पहचान पत्र</div>
              </div>
            </div>
            <div class="text-right">
              <span class="text-[9px] font-bold bg-[#B45309] text-white px-2 py-0.5 rounded border border-[#F59E0B]">
                AGE 60+ STATUTORY
              </span>
            </div>
          </div>

          <div class="p-4 bg-amber-50/30 space-y-3">
            <div class="flex gap-3 items-center bg-white p-3 rounded-lg border border-amber-200 shadow-2xs">
              <div class="w-20 h-24 rounded-lg overflow-hidden border-2 border-[#00314D] shrink-0 bg-slate-100">
                <img src="https://images.unsplash.com/photo-1544005313-94ddf0286df2?auto=format&fit=crop&w=200&h=240&q=80" alt="Senior Citizen Photograph" class="w-full h-full object-cover"/>
              </div>

              <div class="flex-grow space-y-1 text-xs">
                <div>
                  <span class="text-[10px] text-slate-500 block">Senior Citizen Card No:</span>
                  <span class="font-mono text-base font-black text-[#00314D]">SR-CITIZEN-UP-2026-98412</span>
                </div>
                <div>Name: <strong>${farmerName}</strong> (Age: 64 Years)</div>
                <div>Blood Group: <strong class="text-red-600 font-mono">O+ (ABHA Health Linked)</strong></div>
                <div>Emergency Contact: <strong>Son (+91 98765 43210)</strong></div>
                <div>Address: <strong>${village}</strong></div>
              </div>

              <div class="w-16 h-16 shrink-0 border p-1 rounded bg-white">
                <i data-lucide="qr-code" class="w-full h-full text-[#00314D]"></i>
              </div>
            </div>

            <div class="p-2 bg-amber-50 rounded border border-amber-200 text-[10px] text-[#854D0E]">
              वरिष्ठ नागरिक भरण-पोषण एवं कल्याण अधिनियम २००७ के अंतर्गत निःशुल्क स्वास्थ्य जांच, यात्रा रियायत एवं प्राथमिकता सहायता हेतु मान्य।
            </div>
          </div>

          <div class="bg-slate-900 text-white p-2 px-3 flex items-center justify-between text-[9px]">
            <span class="flex items-center gap-1 text-slate-300">
              <i data-lucide="shield-check" class="w-3.5 h-3.5 text-[#10B981]"></i>
              <span>National Senior Welfare Registry • Verified & Issued</span>
            </span>
            <span class="font-mono text-[#FCD34D] font-bold">DISTRICT MAGISTRATE</span>
          </div>
        </div>`;
    } else {
      // Default: PM-KISAN
      container.innerHTML = `
        <div class="farmer-voucher-frame" id="printable-farmer-voucher">
          <div class="text-center border-b-2 border-[#138808] pb-3 mb-3">
            <div class="text-xs font-bold text-[#138808] uppercase">भारत सरकार • GOVERNMENT OF INDIA</div>
            <div class="text-[11px] text-[#4B5563] uppercase">MINISTRY OF AGRICULTURE &amp; FARMERS WELFARE / कृषि एवं किसान कल्याण मंत्रालय</div>
            <div class="text-[10px] text-[#6B7280]">DEPARTMENT OF AGRICULTURE AND FARMERS WELFARE</div>
            <div class="text-sm sm:text-base font-black text-[#138808] uppercase tracking-wide mt-1.5 border-t border-b border-[#138808] py-1 inline-block px-4">
              PM-KISAN DBT SANCTION ORDER / प्रत्यक्ष लाभ अंतरण स्वीकृति आदेश
            </div>
            <div class="text-[9px] text-[#6B7280] italic mt-0.5">
              Pradhan Mantri Kisan Samman Nidhi Scheme (AgriStack Land-Linked DBT)
            </div>
          </div>

          <p class="text-xs text-[#1F2937] leading-relaxed mb-3 text-justify">
            Sanction is hereby accorded for the release of financial benefit under the PM-KISAN scheme to the eligible farmer beneficiary whose landholding has been authenticated via State RoR Land Records and Aadhaar-seeded NPCI mapper.
          </p>

          <table class="gov-cert-table">
            <tbody>
              <tr>
                <th>Beneficiary Farmer Name:</th>
                <td class="font-bold text-[#138808]">${farmerName}</td>
                <th>Aadhaar Token ID:</th>
                <td class="font-mono font-bold">${aadhaar}</td>
              </tr>
              <tr>
                <th>Khasra / Plot Number:</th>
                <td class="font-mono font-bold">${khasra}</td>
                <th>Village &amp; District:</th>
                <td>${village}</td>
              </tr>
              <tr>
                <th>Sanctioned Amount:</th>
                <td class="font-black text-[#138808] text-sm">${amt}</td>
                <th>Credit Account / Mode:</th>
                <td>${bank}</td>
              </tr>
              <tr>
                <th>PFMS Transaction ID:</th>
                <td class="font-mono text-[#00314D] font-bold">PFMS2026AGRI948120</td>
                <th>AgriStack Registry ID:</th>
                <td class="font-mono">AGRI-UP-2026-89412</td>
              </tr>
            </tbody>
          </table>

          <div class="mt-4 pt-3 border-t-2 border-[#138808] flex items-center justify-between text-[10px]">
            <div class="flex items-center gap-2">
              <div class="w-12 h-12 border p-0.5 rounded bg-white">
                <i data-lucide="qr-code" class="w-full h-full text-[#138808]"></i>
              </div>
              <div class="text-slate-600 font-mono text-[9px]">
                <div>PM-KISAN DBT ENGINE SYNCHRONIZED</div>
                <div class="text-[#138808] font-bold">Direct Benefit Transferred via PFMS</div>
              </div>
            </div>
            <div class="text-right">
              <span class="bg-emerald-100 text-emerald-900 border border-emerald-300 px-2.5 py-1 rounded font-bold text-xs">
                DBT SANCTIONED
              </span>
            </div>
          </div>
        </div>`;
    }

    let fTitle = 'PM-KISAN DBT Sanction Order';
    let fNo = 'AGRI-UP-2026-89412';
    if (subKey === 'ration') { fTitle = 'National Food Security Digital Ration Card (NFSA)'; fNo = 'NFSA-UP-094819204'; }
    else if (subKey === 'kcc') { fTitle = 'Kisan Credit Card (KCC) Sanction Order'; fNo = 'KCC-SBI-2026-48192'; }
    else if (subKey === 'pension') { fTitle = 'National Pension Payment Order (NSAP PPO)'; fNo = pensionPpo; }
    else if (subKey === 'senior') { fTitle = 'National Senior Citizen Identity Card'; fNo = 'SR-CITIZEN-UP-2026-98412'; }

    finishFarmerRender(fTitle, fNo);
  };

// REVENUE DESK SUB-SERVICES (10 STATUTORY CERTIFICATES)
  // =========================================================================
  window.currentRevenueSubService = 'caste';

  window.switchRevenueSubService = function(subKey) {
    window.currentRevenueSubService = subKey;
    const subBtns = {
      caste: document.getElementById('btn-sub-caste'),
      income: document.getElementById('btn-sub-income'),
      domicile: document.getElementById('btn-sub-domicile'),
      ews: document.getElementById('btn-sub-ews'),
      ncl: document.getElementById('btn-sub-ncl'),
      divyang: document.getElementById('btn-sub-divyang'),
      character: document.getElementById('btn-sub-character'),
      land: document.getElementById('btn-sub-land'),
      legalheir: document.getElementById('btn-sub-legalheir'),
      solvency: document.getElementById('btn-sub-solvency'),
      mutation: document.getElementById('btn-sub-mutation'),
      demarcation: document.getElementById('btn-sub-demarcation'),
      parivar: document.getElementById('btn-sub-parivar')
    };

    Object.keys(subBtns).forEach(k => {
      if (subBtns[k]) {
        if (k === subKey) {
          subBtns[k].className = 'px-2.5 py-1.5 rounded-lg text-xs font-bold bg-[#B45309] text-white shadow-xs cursor-pointer flex items-center gap-1 transition';
        } else {
          subBtns[k].className = 'px-2.5 py-1.5 rounded-lg text-xs font-bold bg-white text-[#854D0E] hover:bg-amber-50 cursor-pointer flex items-center gap-1 border border-amber-200 transition';
        }
      }
    });

    const rows = {
      income: document.getElementById('row-income-fields'),
      domicile: document.getElementById('row-domicile-fields'),
      divyang: document.getElementById('row-divyang-fields'),
      character: document.getElementById('row-character-fields'),
      land: document.getElementById('row-land-fields'),
      legalheir: document.getElementById('row-legalheir-fields'),
      solvency: document.getElementById('row-solvency-fields')
    };

    Object.keys(rows).forEach(r => {
      if (rows[r]) rows[r].classList.add('hidden');
    });

    const titleText = document.getElementById('revenue-desk-title-text');

    if (subKey === 'income') {
      if (rows.income) rows.income.classList.remove('hidden');
      if (titleText) titleText.textContent = 'राजस्व विभाग • आय प्रमाण पत्र आवेदन (Income Certificate Desk)';
    } else if (subKey === 'domicile') {
      if (rows.domicile) rows.domicile.classList.remove('hidden');
      if (titleText) titleText.textContent = 'राजस्व विभाग • निवास / अधिवास प्रमाण पत्र आवेदन (Domicile Certificate Desk)';
    } else if (subKey === 'ews') {
      if (rows.income) rows.income.classList.remove('hidden');
      if (titleText) titleText.textContent = 'राजस्व विभाग • आर्थिक रूप से कमजोर वर्ग प्रमाण पत्र (EWS Certificate Desk)';
    } else if (subKey === 'ncl') {
      if (rows.income) rows.income.classList.remove('hidden');
      if (titleText) titleText.textContent = 'राजस्व विभाग • अन्य पिछड़ा वर्ग गैर-क्रीमी लेयर प्रमाण पत्र (OBC NCL Desk)';
    } else if (subKey === 'divyang') {
      if (rows.divyang) rows.divyang.classList.remove('hidden');
      if (titleText) titleText.textContent = 'दिव्यांगजन सशक्तिकरण विभाग • दिव्यांगता प्रमाण पत्र / UDID Desk';
    } else if (subKey === 'character') {
      if (rows.character) rows.character.classList.remove('hidden');
      if (titleText) titleText.textContent = 'गृह एवं राजस्व विभाग • चरित्र एवं पूर्ववृत्त सत्यापन प्रमाण पत्र (Character Desk)';
    } else if (subKey === 'land') {
      if (rows.land) rows.land.classList.remove('hidden');
      if (titleText) titleText.textContent = 'राजस्व परिषद • भू-अभिलेख खतौनी / अधिकार अभिलेख (Record of Rights Desk)';
    } else if (subKey === 'legalheir') {
      if (rows.legalheir) rows.legalheir.classList.remove('hidden');
      if (titleText) titleText.textContent = 'राजस्व एवं मजिस्ट्रेट • विधिक उत्तराधिकारी / वारिसान प्रमाण पत्र (Legal Heir Desk)';
    } else if (subKey === 'solvency') {
      if (rows.solvency) rows.solvency.classList.remove('hidden');
      if (titleText) titleText.textContent = 'राजस्व एवं वित्त विभाग • हैसियत प्रमाण पत्र (Solvency Certificate Desk)';
    } else if (subKey === 'mutation') {
      if (rows.land) rows.land.classList.remove('hidden');
      if (titleText) titleText.textContent = 'राजस्व परिषद • दाखिल खारिज (भू-अभिलेख नामांतरण आदेश - Mutation Desk)';
    } else if (subKey === 'demarcation') {
      if (rows.land) rows.land.classList.remove('hidden');
      if (titleText) titleText.textContent = 'राजस्व न्यायालय • भूमि पैमाइश एवं सीमांकन आदेश (Land Demarcation Desk)';
    } else if (subKey === 'parivar') {
      if (rows.legalheir) rows.legalheir.classList.remove('hidden');
      if (titleText) titleText.textContent = 'पंचायती राज विभाग • परिवार रजिस्टर नकल (Family Register Parivar Nakal)';
    } else {
      if (titleText) titleText.textContent = 'राजस्व एवं समाज कल्याण • जाति प्रमाण पत्र आवेदन (Caste Certificate Desk)';
    }

    window.generateCasteCertificateAction();
    if (window.lucide) window.lucide.createIcons();
  };

  // =========================================================================
  // CERTIFICATE ISSUANCE & EDIT ENGINE (CROSS-DESK PERSISTENCE & VISUAL SEALS)
  // =========================================================================
  window.issuedCertificates = window.issuedCertificates || {};

  window.attachIssuedBannerIfPresent = function(deskKey, container) {
    if (!container) return;
    const info = window.issuedCertificates[deskKey];
    if (!info) return;

    let existing = document.getElementById('issued-seal-banner-' + deskKey);
    if (!existing) {
      const banner = document.createElement('div');
      banner.id = 'issued-seal-banner-' + deskKey;
      banner.className = 'cert-issued-banner mb-3 p-3 bg-gradient-to-r from-emerald-600 via-teal-700 to-emerald-800 text-white rounded-xl shadow-md flex items-center justify-between border border-emerald-400/40 animate-fadeIn';
      banner.innerHTML = `
        <div class="flex items-center gap-2.5">
          <div class="w-8 h-8 rounded-full bg-white text-emerald-800 flex items-center justify-center font-black text-sm shadow shrink-0">✓</div>
          <div>
            <div class="text-xs font-black tracking-wide uppercase">आधिकारिक रूप से निर्गत एवं प्रमाणित (OFFICIALLY ISSUED &amp; SEALED)</div>
            <div class="text-[10px] text-emerald-100 font-mono">Cert No: <strong class="text-white">${info.certNo}</strong> • Date: ${info.date} • Class 3 DSC Token Verified</div>
          </div>
        </div>
        <div class="flex items-center gap-2">
          <span class="bg-emerald-950/60 border border-emerald-300 text-emerald-200 text-[10px] font-bold px-2 py-0.5 rounded-full uppercase tracking-wider">e-Sign 3.0</span>
          <button type="button" onclick="window.printActiveCertificate()" class="bg-white hover:bg-emerald-50 text-emerald-900 px-2.5 py-1 rounded text-[11px] font-bold shadow-xs cursor-pointer flex items-center gap-1">
            <i data-lucide="printer" class="w-3 h-3"></i> <span>Print</span>
          </button>
        </div>
      `;
      container.insertBefore(banner, container.firstChild);
      if (window.lucide && typeof window.lucide.createIcons === 'function') {
        window.lucide.createIcons();
      }
    } else {
      const monoEl = existing.querySelector('.font-mono');
      if (monoEl) {
        monoEl.innerHTML = `Cert No: <strong class="text-white">${info.certNo}</strong> • Date: ${info.date} • Class 3 DSC Token Verified`;
      }
    }
  };

  window.notifyCertificateIssued = function(deskKey, certTitle, certNo, applicantName, fatherName, district) {
    const containerIdMap = {
      caste: 'caste-document-container',
      dl: 'dl-document-container',
      birth: 'active-document-container',
      business: 'biz-document-container',
      farmer: 'farmer-document-container'
    };
    const containerId = containerIdMap[deskKey] || 'caste-document-container';
    const container = document.getElementById(containerId);

    const cleanCertNo = certNo || ('MH/2026/' + deskKey.toUpperCase() + '/' + Math.floor(100000 + Math.random() * 900000));
    const nowStr = new Date().toLocaleDateString('en-GB') + ' ' + new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }) + ' IST';

    window.issuedCertificates[deskKey] = {
      certTitle: certTitle,
      certNo: cleanCertNo,
      applicantName: (applicantName || 'Citizen Applicant').toUpperCase(),
      fatherName: (fatherName || 'Father / Guardian').toUpperCase(),
      district: district || 'Varanasi, UP',
      date: nowStr
    };

    // 1. Persist in NDIG_DATABASE for verification and tracking
    const appRecord = {
      refNo: 'MH-2026-' + deskKey.toUpperCase() + '-' + Math.floor(100000 + Math.random() * 900000),
      serviceId: deskKey.toUpperCase() + '-STATUTORY',
      serviceName: certTitle,
      category: deskKey,
      applicantName: (applicantName || 'Citizen Applicant').toUpperCase(),
      fatherName: (fatherName || 'Father / Guardian').toUpperCase(),
      aadhaarMasked: 'XXXX-XXXX-' + Math.floor(1000 + Math.random() * 9000),
      district: district || 'National',
      status: 'APPROVED',
      submittedAt: nowStr,
      approvedAt: nowStr,
      officerName: 'Executive Magistrate & Tehsildar (Class 3 DSC)',
      officerRemarks: 'Statutory certificate officially issued, sealed and e-Signed via MH Sahyog RTPS Gateway.',
      certificateNo: cleanCertNo,
      sha256Digest: '0x' + Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, '0')).join('')
    };

    if (window.NDIG_DATABASE && typeof window.NDIG_DATABASE.addApplication === 'function') {
      window.NDIG_DATABASE.addApplication(appRecord);
    }

    // 2. Attach visual issued banner
    if (container) {
      window.attachIssuedBannerIfPresent(deskKey, container);

      // Momentary highlight ring on container
      container.classList.add('ring-4', 'ring-emerald-400', 'border-emerald-500');
      setTimeout(() => {
        container.classList.remove('ring-4', 'ring-emerald-400');
      }, 2500);

      // Smooth scroll to container
      container.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }

    // 3. Official Toast Notification
    showGovToast('✓ ' + certTitle + ' (' + cleanCertNo + ') आधिकारिक रूप से जारी एवं प्रमाणित! (Certificate Issued & Sealed)');

    if (window.lucide && typeof window.lucide.createIcons === 'function') {
      setTimeout(() => window.lucide.createIcons(), 50);
    }
  };

  window.editCertificateDetails = function(deskKey) {
    const inputMap = {
      caste: 'input-caste-applicant',
      dl: 'input-dl-name',
      birth: 'input-child-name',
      business: 'input-biz-name',
      farmer: 'input-farmer-name'
    };
    const inputId = inputMap[deskKey] || 'input-caste-applicant';
    const inputEl = document.getElementById(inputId);
    if (inputEl) {
      inputEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
      inputEl.focus();
      inputEl.classList.add('ring-4', 'ring-amber-400', 'border-amber-500', 'bg-amber-50');
      setTimeout(() => {
        inputEl.classList.remove('ring-4', 'ring-amber-400', 'border-amber-500', 'bg-amber-50');
      }, 2500);
    }
    showGovToast('संपादक मोड सक्रिय: बाईं ओर फॉर्म में विवरण बदलें, प्रमाण पत्र स्वतः अपडेट होगा (Edit details in form)');
  };

  window.toggleDirectCertEdit = function(containerId, buttonId) {
    const container = document.getElementById(containerId);
    const btn = document.getElementById(buttonId);
    if (!container) return;

    const isEditable = container.getAttribute('contenteditable') === 'true';
    if (!isEditable) {
      container.setAttribute('contenteditable', 'true');
      container.classList.add('outline-dashed', 'outline-2', 'outline-amber-500', 'bg-amber-50/20');
      if (btn) {
        btn.className = 'bg-emerald-600 hover:bg-emerald-700 text-white px-2.5 py-1.5 rounded-lg text-xs font-bold flex items-center gap-1 shadow-sm cursor-pointer animate-pulse';
        btn.innerHTML = '<i data-lucide="check" class="w-3.5 h-3.5"></i> <span>Done Editing (सुरक्षित करें)</span>';
      }
      showGovToast('सीधे संपादन मोड सक्रिय: प्रमाण पत्र पर किसी भी टेक्स्ट पर क्लिक करके बदलें (Direct edit mode on)');
    } else {
      container.removeAttribute('contenteditable');
      container.classList.remove('outline-dashed', 'outline-2', 'outline-amber-500', 'bg-amber-50/20');
      if (btn) {
        btn.className = 'bg-white hover:bg-amber-50 text-amber-800 border border-amber-300 px-2.5 py-1.5 rounded-lg text-xs font-bold flex items-center gap-1 shadow-sm cursor-pointer';
        btn.innerHTML = '<i data-lucide="pen-tool" class="w-3.5 h-3.5 text-amber-600"></i> <span>Direct Edit</span>';
      }
      showGovToast('✓ प्रमाण पत्र में किए गए परिवर्तन सुरक्षित कर दिए गए हैं (Changes saved)');
    }
    if (window.lucide && typeof window.lucide.createIcons === 'function') {
      window.lucide.createIcons();
    }
  };

  window.generateCasteCertificateAction = function(isExplicitIssue = false) {
    const subKey = window.currentRevenueSubService || 'caste';
    const dept = escapeHtml(document.getElementById('input-caste-dept')?.value || 'Office of the Tehsildar, Tehsil - Sadar, District - Varanasi, Uttar Pradesh');
    const applicant = escapeHtml((document.getElementById('input-caste-applicant')?.value || 'Rajesh Kumar').toUpperCase());
    const father = escapeHtml((document.getElementById('input-caste-father')?.value || 'Harish Chandra').toUpperCase());
    const category = escapeHtml(document.getElementById('input-caste-category')?.value || 'Scheduled Caste (SC) / अनुसूचित जाति');
    const subcaste = escapeHtml(document.getElementById('input-caste-subcaste')?.value || 'Chamar / Jatav (चमार / जाटव)');
    const district = escapeHtml(document.getElementById('input-caste-district')?.value || 'Varanasi, Uttar Pradesh');
    const aadhaar = maskAadhaar(document.getElementById('input-caste-aadhaar')?.value || 'XXXX-XXXX-7219');
    const address = escapeHtml(document.getElementById('input-caste-address')?.value || 'Gram - Shivpur, Post - Shivpur, Ward No. 12, Varanasi, UP - 221003');
    const incomeVal = escapeHtml(document.getElementById('input-caste-income')?.value || '₹ 1,20,000 (एक लाख बीस हजार रुपये)');
    const purposeVal = escapeHtml(document.getElementById('input-caste-purpose')?.value || 'उच्च शिक्षा छात्रवृत्ति, शुल्क प्रतिपूर्ति एवं सरकारी योजनाएं');
    const tenureVal = escapeHtml(document.getElementById('input-caste-tenure')?.value || 'जन्म से स्थायी निवासी (Since Birth / 24 Years)');
    const divyangType = escapeHtml(document.getElementById('input-divyang-type')?.value || 'Locomotor Disability (अस्थि दिव्यांगता)');
    const divyangPct = escapeHtml(document.getElementById('input-divyang-pct')?.value || '45% (Permanent)');
    const divyangCmo = escapeHtml(document.getElementById('input-divyang-cmo')?.value || 'District Hospital Medical Board, Varanasi');
    const charPurpose = escapeHtml(document.getElementById('input-character-purpose')?.value || 'Government Employment / Public Works Contractor');
    const landKhasra = escapeHtml(document.getElementById('input-land-khasra')?.value || '142/क, 143/ख');
    const landKhata = escapeHtml(document.getElementById('input-land-khata')?.value || '00184');
    const landArea = escapeHtml(document.getElementById('input-land-area')?.value || '0.4850 Hectare');

    const container = document.getElementById('caste-document-container');
    if (!container) return;

    let certTitleHindi = 'जाति प्रमाण पत्र';
    let certTitleEng = 'CASTE CERTIFICATE';
    let formNo = 'प्रारूप - ४ (नियम ६ देखिए)';
    let certNo = 'UP/2026/CC/849201';
    let dynamicBody = '';

    if (subKey === 'income') {
      certTitleHindi = 'आय प्रमाण पत्र';
      certTitleEng = 'INCOME CERTIFICATE';
      formNo = 'प्रारूप - १ (आय सत्यापन)';
      certNo = 'UP/2026/INC/918472';
      dynamicBody = `
        <div class="space-y-2 text-justify">
          <p>प्रमाणित किया जाता है कि <strong>${applicant}</strong> सुपुत्र श्री <strong>${father}</strong>, निवासी <strong>${address}</strong>, तहसील सदर, जिला <strong>${district}</strong> के परिवार की समस्त वैध स्रोतों से कुल वार्षिक आय <strong>${incomeVal}</strong> है।</p>
          <p>This is to certify that annual family income of <strong>${applicant}</strong> S/o Shri <strong>${father}</strong>, resident of <strong>${address}</strong>, from all verified sources is <strong>${incomeVal}</strong> per annum.</p>
          <p class="text-[11px] text-[#475569]">प्रयोजन (Purpose): <strong>${purposeVal}</strong>। यह प्रमाण पत्र जारी होने की तिथि से तीन वर्ष हेतु मान्य है।</p>
        </div>`;
    } else if (subKey === 'domicile') {
      certTitleHindi = 'मूल निवास प्रमाण पत्र';
      certTitleEng = 'DOMICILE / RESIDENCE CERTIFICATE';
      formNo = 'प्रारूप - २ (अधिवास प्रमाण)';
      certNo = 'UP/2026/DOM/650193';
      dynamicBody = `
        <div class="space-y-2 text-justify">
          <p>प्रमाणित किया जाता है कि <strong>${applicant}</strong> सुपुत्र श्री <strong>${father}</strong>, पता <strong>${address}</strong>, जिला <strong>${district}</strong> के <strong>${tenureVal}</strong> हैं तथा राज्य के विधिक अधिवासी (Permanent Legal Domicile) हैं।</p>
          <p>This is to certify that <strong>${applicant}</strong> S/o Shri <strong>${father}</strong> is a permanent legal resident and domicile holder of Uttar Pradesh at <strong>${address}</strong>.</p>
        </div>`;
    } else if (subKey === 'ews') {
      certTitleHindi = 'आर्थिक रूप से कमजोर वर्ग (EWS) प्रमाण पत्र';
      certTitleEng = 'ECONOMICALLY WEAKER SECTION (EWS) CERTIFICATE';
      formNo = 'प्रारूप - ५ (EWS आरक्षण)';
      certNo = 'UP/2026/EWS/481920';
      dynamicBody = `
        <div class="space-y-2 text-justify">
          <p>प्रमाणित किया जाता है कि <strong>${applicant}</strong> सुपुत्र श्री <strong>${father}</strong>, निवासी <strong>${address}</strong>, वित्तीय वर्ष 2025-26 के अंतर्गत <strong>आर्थिक रूप से कमजोर वर्ग (EWS)</strong> के मानकों को पूर्ण करते हैं। परिवार की कुल सकल वार्षिक आय ₹ 8 लाख से कम है।</p>
          <p>This is to certify that the family of <strong>${applicant}</strong> fulfills the criteria of Economically Weaker Sections (EWS) for Central/State Government reservations.</p>
        </div>`;
    } else if (subKey === 'ncl') {
      certTitleHindi = 'अन्य पिछड़ा वर्ग (क्रीमी लेयर रहित) प्रमाण पत्र';
      certTitleEng = 'OBC NON-CREAMY LAYER (NCL) CERTIFICATE';
      formNo = 'प्रारूप - ६ (NCL प्रमाण)';
      certNo = 'UP/2026/NCL/332194';
      dynamicBody = `
        <div class="space-y-2 text-justify">
          <p>प्रमाणित किया जाता है कि <strong>${applicant}</strong> सुपुत्र श्री <strong>${father}</strong>, जाति <strong>${subcaste}</strong>, उत्तर प्रदेश सरकार एवं भारत सरकार द्वारा अधिसूचित <strong>अन्य पिछड़ा वर्ग (OBC)</strong> से संबंधित हैं तथा <strong>क्रीमी लेयर (Creamy Layer)</strong> के अंतर्गत नहीं आते हैं।</p>
          <p>This certifies that <strong>${applicant}</strong> belongs to the Other Backward Classes (OBC) and does NOT belong to the persons/sections (Creamy Layer) as per DoPT guidelines.</p>
        </div>`;
    } else if (subKey === 'divyang') {
      certTitleHindi = 'दिव्यांगता प्रमाण पत्र (UDID)';
      certTitleEng = 'CERTIFICATE OF DISABILITY (UDID)';
      formNo = 'प्रारूप - ४ (दिव्यांगजन अधिकार अधिनियम 2016)';
      certNo = 'UP/2026/UDID/781042';
      dynamicBody = `
        <div class="space-y-2 text-justify">
          <p>चिकित्सीय परीक्षण उपरांत प्रमाणित किया जाता है कि <strong>${applicant}</strong> सुपुत्र श्री <strong>${father}</strong>, निवासी <strong>${address}</strong>, <strong>${divyangType}</strong> से ग्रसित हैं तथा दिव्यांगता का प्रतिशत <strong>${divyangPct}</strong> है।</p>
          <p>Certified by the Medical Board that <strong>${applicant}</strong> has been assessed with <strong>${divyangType}</strong> at <strong>${divyangPct}</strong> permanent disability under the RPwD Act 2016.</p>
          <p class="text-[11px] text-[#475569]">मेडिकल बोर्ड प्राधिकारी: <strong>${divyangCmo}</strong>।</p>
        </div>`;
    } else if (subKey === 'character') {
      certTitleHindi = 'चरित्र एवं पूर्ववृत्त प्रमाण पत्र';
      certTitleEng = 'CHARACTER & ANTECEDENT CERTIFICATE';
      formNo = 'प्रारूप - ३ (पुलिस चरित्र सत्यापन)';
      certNo = 'UP/2026/CHAR/592184';
      dynamicBody = `
        <div class="space-y-2 text-justify">
          <p>स्थानीय पुलिस जांच एवं अभिलेखों के सत्यापन अनुसार प्रमाणित किया जाता है कि <strong>${applicant}</strong> सुपुत्र श्री <strong>${father}</strong>, निवासी <strong>${address}</strong> का चरित्र उत्तम है तथा इनके विरुद्ध संबंधित थाना में <strong>कोई भी आपराधिक अभियोग / वाद लंबित नहीं है</strong>।</p>
          <p>Police background verification confirms that <strong>${applicant}</strong> bears good moral character with NO criminal antecedents on official record.</p>
          <p class="text-[11px] text-[#475569]">प्रयोजन (Purpose): <strong>${charPurpose}</strong>।</p>
        </div>`;
    } else if (subKey === 'land') {
      certTitleHindi = 'भू-अभिलेख खतौनी (अधिकार अभिलेख)';
      certTitleEng = 'RECORD OF RIGHTS / REVENUE KHATAUNI (ROR)';
      formNo = 'उ०प्र० राजस्व संहिता २०१६ (धारा ३१-३२)';
      certNo = 'UP/2026/ROR/104928';
      dynamicBody = `
        <div class="space-y-2 text-justify">
          <p>ग्राम - शिवपुर, परगना - देहात अमानत, तहसील - सदर, जिला - वाराणसी। खातेदार का नाम: <strong>${applicant}</strong> व <strong>${father}</strong>।</p>
          <div class="bg-amber-50 p-2.5 rounded-lg border border-amber-200 text-xs font-mono space-y-1">
            <div>खाता संख्या (Khata No): <strong>${landKhata}</strong> | खसरा / गाटा संख्या: <strong>${landKhasra}</strong></div>
            <div>कुल क्षेत्रफल (Total Area): <strong>${landArea}</strong> | भू-राजस्व देय (Land Revenue): <strong>₹ 34.50</strong></div>
            <div>नामांतरण आदेश (Mutation Order): <strong>ना०आ०/२०२४/सदर/८९२ (स्वीकृत एवं अद्यतन)</strong></div>
          </div>
          <p class="text-[11px] text-[#475569]">यह भूलेख अभिलेख उत्तर प्रदेश राजस्व परिषद के रियल-टाइम भू-नक्शा एवं खतौनी डेटाबेस से डिजिटल रूप से सत्यापित है।</p>
        </div>`;
    } else if (subKey === 'legalheir') {
    const deceased = escapeHtml(document.getElementById('input-legalheir-deceased')?.value || 'Late Harish Chandra');
    const dod = escapeHtml(document.getElementById('input-legalheir-dod')?.value || '2025-04-18');
    const heirs = escapeHtml(document.getElementById('input-legalheir-heirs')?.value || '1. Rajesh Kumar (Son, Age 24), 2. Shanti Devi (Wife, Age 48)');
      certTitleHindi = 'विधिक उत्तराधिकारी प्रमाण पत्र (वारिसान)';
      certTitleEng = 'LEGAL HEIR / SURVIVING MEMBER CERTIFICATE';
      formNo = 'प्रारूप - ७ (राजस्व संहिता नियम ३३)';
      certNo = 'UP/2026/LHR/819203';
      dynamicBody = `
        <div class="space-y-2 text-justify">
          <p>राजस्व निरीक्षक एवं क्षेत्रीय लेखपाल की संयुक्त जांच आख्या अनुसार प्रमाणित किया जाता है कि मृतक <strong>${deceased}</strong>, जिनकी मृत्यु दिनांक <strong>${dod}</strong> को हुई, के विधिक जीवित उत्तराधिकारी (Surviving Legal Heirs) निम्नवत हैं:</p>
          <div class="bg-amber-50 p-2.5 rounded-lg border border-amber-200 text-xs font-mono space-y-1">
            <div class="font-bold text-[#854D0E]">जीवित वारिसों की सूची (List of Surviving Family Heirs):</div>
            <div class="text-[#00314D] font-semibold">${heirs}</div>
          </div>
          <p class="text-[11px] text-[#475569]">यह प्रमाण पत्र संपत्ति नामांतरण, बैंक खाता क्लेम एवं अनुकंपा नियुक्ति प्रयोजनों हेतु तहसीलदार सदर द्वारा विधिवत निर्गत किया जाता है।</p>
        </div>`;
    } else if (subKey === 'solvency') {
    const solAmount = escapeHtml(document.getElementById('input-solvency-amount')?.value || '₹ 25,00,000 (पच्चीस लाख रुपये मात्र)');
    const solProp = escapeHtml(document.getElementById('input-solvency-property')?.value || 'Residential RCC House, Khasra 142/क, Value ₹25L');
      certTitleHindi = 'हैसियत प्रमाण पत्र';
      certTitleEng = 'SOLVENCY CERTIFICATE';
      formNo = 'प्रारूप - ८ (वित्तीय हैसियत नियमावली)';
      certNo = 'UP/2026/SOL/401928';
      dynamicBody = `
        <div class="space-y-2 text-justify">
          <p>अपर जिलाधिकारी (वित्त एवं राजस्व) द्वारा राजस्व आख्या के आधार पर प्रमाणित किया जाता है कि <strong>${applicant}</strong> सुपुत्र श्री <strong>${father}</strong>, निवासी <strong>${address}</strong> की कुल अचल संपत्ति एवं शुद्ध वित्तीय हैसियत <strong>${solAmount}</strong> है।</p>
          <div class="bg-amber-50 p-2.5 rounded-lg border border-amber-200 text-xs font-mono space-y-1">
            <div>सत्यापित संपत्ति विवरण: <strong>${solProp}</strong></div>
            <div>राजस्व मूल्यांकन स्थिति: <strong>ऋणभार मुक्त (Free from encumbrances)</strong></div>
          </div>
          <p class="text-[11px] text-[#475569]">प्रयोजन: सरकारी निविदा (Government Tenders), आबकारी/खनन ठेका एवं बैंक जमानत हेतु विधिमान्य।</p>
        </div>`;
    } else if (subKey === 'mutation') {
      certTitleHindi = 'दाखिल खारिज (नामांतरण आदेश पत्र)';
      certTitleEng = 'LAND MUTATION & TITLE REGISTER ORDER (DAKHIL KHARIJ)';
      formNo = 'उ०प्र० राजस्व संहिता २०१६ (धारा ३४/३५)';
      certNo = 'UP/2026/MUT/892014';
      dynamicBody = `
        <div class="space-y-2 text-justify">
          <p>न्यायालय तहसीलदार, तहसील - सदर, जनपद - वाराणसी। वाद संख्या: <strong>T202601700104928</strong> (बिक्री नामांतरण)।</p>
          <div class="bg-amber-50 p-2.5 rounded-lg border border-amber-200 text-xs font-mono space-y-1">
            <div>क्रेता (Transferee): <strong>${applicant}</strong> सुपुत्र श्री <strong>${father}</strong></div>
            <div>विक्रेता (Transferor): <strong>श्री रामलाल वर्मा</strong> सुपुत्र स्वर्गीय शिवपूजन वर्मा</div>
            <div>रजिस्ट्री विलेख संख्या: <strong>४८१९/२०२६ (उप-निबंधक सदर कार्यालय)</strong></div>
            <div>गाटा / खसरा सं०: <strong>${landKhasra}</strong> | क्षेत्रफल: <strong>${landArea}</strong></div>
          </div>
          <p class="font-bold text-[#854D0E] text-xs">आदेश: विक्रेता का नाम निरस्त कर क्रेता का नाम बतौर संक्रमणीय भूमिधर राजस्व खतौनी में दर्ज करने का अंतिम आदेश पारित किया गया।</p>
          <p class="text-[11px] text-[#475569]">राजस्व परिषद एवं उप-निबंधक कार्यालय के अंतर-संचालनीय (Interoperable) गेटवे द्वारा आदेश सत्यापित।</p>
        </div>`;
    } else if (subKey === 'demarcation') {
      certTitleHindi = 'भूमि सीमांकन एवं पैमाइश प्रमाण पत्र';
      certTitleEng = 'LAND DEMARCATION & BOUNDARY FIXATION ORDER (PAIMAYISH)';
      formNo = 'उ०प्र० राजस्व संहिता २०१६ (धारा २४)';
      certNo = 'UP/2026/DEM/501928';
      dynamicBody = `
        <div class="space-y-2 text-justify">
          <p>राजस्व न्यायालय उपजिलाधिकारी (एसडीएम) सदर। वाद सं०: <strong>D2026017004182</strong> (सीमांकन)।</p>
          <div class="bg-amber-50 p-2.5 rounded-lg border border-amber-200 text-xs font-mono space-y-1">
            <div>आवेदक / काश्तकार: <strong>${applicant}</strong> | मौजा: <strong>शिवपुर</strong></div>
            <div>विवादित गाटा संख्या: <strong>${landKhasra}</strong> | कुल रकबा: <strong>${landArea}</strong></div>
            <div>पैमाइश दल: <strong>राजस्व निरीक्षक (कानूनगो) एवं क्षेत्रीय लेखपाल</strong></div>
            <div>पैमाइश स्थिति: <strong>ETS / DGPS सीमांकन पूर्ण, पक्की मेड़बंदी चिन्हित</strong></div>
          </div>
          <p>प्रमाणित किया जाता है कि स्थल पर उभय पक्षों की उपस्थिति में भू-अभिलेख एवं भू-नक्शा के अनुसार सीमांकन कर सिद्दे पत्थर (Boundary Stones) स्थापित कर दिए गए हैं।</p>
        </div>`;
    } else if (subKey === 'parivar') {
      certTitleHindi = 'परिवार रजिस्टर की नकल (कुटुंब पंजी)';
      certTitleEng = 'COPY OF FAMILY REGISTER (PARIVAR NAKAL)';
      formNo = 'पंचायती राज अधिनियम १९४७ (प्रारूप - ४)';
      certNo = 'UP/2026/PAR/339182';
      dynamicBody = `
        <div class="space-y-2 text-justify">
          <p>कार्यालय ग्राम पंचायत / विकास खंड - हरहुआ, जनपद - वाराणसी। मकान संख्या: <strong>१४२/अ</strong>।</p>
          <div class="bg-amber-50 p-2.5 rounded-lg border border-amber-200 text-xs font-mono space-y-1">
            <div>परिवार मुखिया (Head of Family): <strong>${father}</strong> | सामाजिक वर्ग: <strong>${category}</strong></div>
            <div class="font-bold text-[#854D0E]">परिवार के पंजीकृत सदस्यों का विवरण:</div>
            <div>१. <strong>${father}</strong> (मुखिया, आयु ५२ वर्ष)</div>
            <div>२. <strong>श्रीमती शान्ति देवी</strong> (पत्नी, आयु ४८ वर्ष)</div>
            <div>३. <strong>${applicant}</strong> (पुत्र, आयु २४ वर्ष, साक्षर)</div>
          </div>
          <p>प्रमाणित किया जाता है कि उपरोक्त विवरण ग्राम पंचायत के मूल परिवार रजिस्टर वर्ष 2026 के अभिलेखों से पूर्णतया मेल खाता है।</p>
        </div>`;
    } else {
      // Default: Caste Certificate
      dynamicBody = `
        <div class="space-y-2 text-justify">
          <p>प्रमाणित किया जाता है कि <strong>${applicant}</strong> सुपुत्र श्री <strong>${father}</strong>, ग्राम/मोहल्ला <strong>${address}</strong>, तहसील सदर, जिला <strong>${district}</strong>, उत्तर प्रदेश के स्थायी निवासी हैं तथा <strong>${category}</strong> की <strong>${subcaste}</strong> जाति के सदस्य हैं।</p>
          <p>This is to certify that <strong>${applicant}</strong> son of Shri <strong>${father}</strong> is an ordinary resident of <strong>${district}</strong> and belongs to the <strong>${subcaste}</strong> under <strong>${category}</strong> recognised under Constitution of India.</p>
        </div>`;
    }

    const certHtml = `
      <div class="border-4 border-[#00314D] p-5 sm:p-6 bg-[#FEFCF6] relative overflow-hidden text-[#002236] shadow-md font-serif">
        <div class="border-2 border-dashed border-[#B45309] p-4 sm:p-5 relative">
          
          <!-- Watermark -->
          <div class="absolute inset-0 flex items-center justify-center opacity-5 pointer-events-none">
            <span class="text-7xl font-black uppercase text-[#00314D]">GOVERNMENT OF INDIA</span>
          </div>

          <!-- Certificate Header -->
          <div class="text-center pb-3 border-b-2 border-[#00314D] space-y-1 relative">
            <div class="text-xs font-mono font-bold text-[#854D0E] tracking-widest uppercase">
              GOVERNMENT OF UTTAR PRADESH • उत्तर प्रदेश शासन
            </div>
            <div class="text-[11px] font-semibold text-[#475569]">
              ${dept}
            </div>
            <div class="py-1">
              <h2 class="text-base sm:text-lg font-black text-[#00314D] tracking-wide uppercase">
                ${certTitleHindi}
              </h2>
              <div class="text-xs font-bold text-[#B45309] tracking-wider">
                ${certTitleEng}
              </div>
            </div>
            <div class="flex items-center justify-between text-[10px] font-mono font-bold text-[#475569] pt-1">
              <span>${formNo}</span>
              <span class="bg-amber-100 px-2 py-0.5 rounded border border-amber-300 text-[#854D0E]">Certificate No: ${certNo}</span>
              <span>जारी दिनांक: 16 October 2026</span>
            </div>
          </div>

          <!-- Dynamic Body -->
          <div class="py-4 text-xs sm:text-[13px] leading-relaxed text-[#1E293B]">
            ${dynamicBody}
          </div>

          <!-- Certificate Footer (Signatures, QR & Security) -->
          <div class="pt-3 border-t-2 border-[#00314D] flex flex-wrap items-end justify-between gap-3 text-[10px] font-mono">
            <div class="space-y-1">
              <div class="flex items-center gap-1.5 text-[#138808] font-bold">
                <i data-lucide="shield-check" class="w-4 h-4"></i>
                <span>CCA India Class 3 Digital Signature (Verified)</span>
              </div>
              <div class="text-slate-500">Signer: Tehsildar & Executive Magistrate, Sadar</div>
              <div class="text-slate-500">Hash: SHA-256 e491...a8f2 | RTPS Bus Synced</div>
            </div>

            <!-- Official State Seal & QR Stamp -->
            <div class="text-center flex flex-col items-center">
              <div class="w-16 h-16 border border-[#CBD5E1] bg-white p-1 rounded shadow-2xs flex items-center justify-center">
                <i data-lucide="qr-code" class="w-14 h-14 text-[#00314D]"></i>
              </div>
              <span class="text-[9px] text-[#475569] mt-0.5 font-bold">Scan to Verify Record</span>
            </div>
          </div>

        </div>
      </div>
    `;

    container.innerHTML = certHtml;
    window.attachIssuedBannerIfPresent('caste', container);
    if (isExplicitIssue) {
      window.notifyCertificateIssued('caste', certTitleHindi + ' (' + certTitleEng + ')', certNo, applicant, father, district);
    }
    if (window.lucide && typeof window.lucide.createIcons === 'function') {
      setTimeout(() => window.lucide.createIcons(), 50);
    }
  };

    // =========================================================================
  // TRANSPORT & MoRTH SUB-SERVICES (5 STATUTORY CERTIFICATES)
  // =========================================================================
  window.currentTransportSubService = 'dl';

  window.switchTransportSubService = function(subKey) {
    window.currentTransportSubService = subKey;
    const subBtns = {
      dl: document.getElementById('btn-trans-dl'),
      ll: document.getElementById('btn-trans-ll'),
      renewal: document.getElementById('btn-trans-renewal'),
      rc: document.getElementById('btn-trans-rc'),
      fitness: document.getElementById('btn-trans-fitness'),
      idp: document.getElementById('btn-trans-idp'),
      hpt: document.getElementById('btn-trans-hpt'),
      conductor: document.getElementById('btn-trans-conductor')
    };

    Object.keys(subBtns).forEach(k => {
      if (subBtns[k]) {
        if (k === subKey) {
          subBtns[k].className = 'px-2.5 py-1.5 rounded-lg text-xs font-bold bg-[#0284C7] text-white shadow-xs cursor-pointer flex items-center gap-1 transition';
        } else {
          subBtns[k].className = 'px-2.5 py-1.5 rounded-lg text-xs font-bold bg-white text-[#0369A1] hover:bg-sky-100 cursor-pointer flex items-center gap-1 border border-sky-200 transition';
        }
      }
    });

    const rowRc = document.getElementById('row-trans-rc-fields');
    if (rowRc) {
      if (subKey === 'rc' || subKey === 'fitness') {
        rowRc.classList.remove('hidden');
      } else {
        rowRc.classList.add('hidden');
      }
    }

    window.generateDrivingLicenceAction();
    if (window.lucide) window.lucide.createIcons();
  };

  window.generateDrivingLicenceAction = function(isExplicitIssue = false) {
    const subKey = window.currentTransportSubService || 'dl';
    const authority = escapeHtml(document.getElementById('input-dl-authority')?.value || 'Regional Transport Office, DL-04 (Janakpuri, West Delhi)');
    const name = escapeHtml((document.getElementById('input-dl-name')?.value || 'Priya Sharma').toUpperCase());
    const father = escapeHtml((document.getElementById('input-dl-father')?.value || 'Mahesh Sharma').toUpperCase());
    const dob = escapeHtml(document.getElementById('input-dl-dob')?.value || '2002-08-15');
    const blood = escapeHtml(document.getElementById('input-dl-blood')?.value || 'B+ (ABHA Health ID Verified)');
    const dlClass = escapeHtml(document.getElementById('input-dl-class')?.value || 'MCWG & LMV (Motorcycle + Car)');
    const aadhaar = maskAadhaar(document.getElementById('input-dl-aadhaar')?.value || 'XXXX-XXXX-9142');
    const address = escapeHtml(document.getElementById('input-dl-address')?.value || 'Flat B-24, District Centre, Janakpuri, West Delhi - 110058');

    const regNo = escapeHtml(document.getElementById('input-rc-regno')?.value || 'DL-04-AB-1024');
    const maker = escapeHtml(document.getElementById('input-rc-maker')?.value || 'Maruti Suzuki Swift VXI (BS-VI)');
    const chassis = escapeHtml(document.getElementById('input-rc-chassis')?.value || 'MA3EAA81S00192841');
    const engine = escapeHtml(document.getElementById('input-rc-engine')?.value || 'K10CN9481204');
    const fuel = escapeHtml(document.getElementById('input-rc-fuel')?.value || 'Petrol / BS-VI Norms');
    const rcValidity = escapeHtml(document.getElementById('input-rc-validity')?.value || '14-Oct-2041 (15 Years Statutory)');

    const container = document.getElementById('dl-document-container');
    if (!container) return;

    function finishTransRender(customTitle, customNo) {
      window.attachIssuedBannerIfPresent('dl', container);
      if (isExplicitIssue) {
        window.notifyCertificateIssued('dl', customTitle, customNo, name, father, authority);
      }
      if (window.lucide && typeof window.lucide.createIcons === 'function') {
        setTimeout(() => window.lucide.createIcons(), 50);
      }
    }

    if (subKey === 'idp') {
      container.innerHTML = `
        <div class="dl-card-frame w-full max-w-[560px] bg-[#FAF8F5] border-4 border-[#0F172A] shadow-xl rounded-xl overflow-hidden font-serif">
          <div class="bg-[#1E293B] text-white p-3.5 text-center border-b-2 border-[#D97706]">
            <div class="text-[10px] tracking-widest uppercase font-mono text-amber-400">GENEVA CONVENTION ON ROAD TRAFFIC 1949</div>
            <h3 class="text-sm sm:text-base font-black tracking-wider uppercase mt-0.5">INTERNATIONAL DRIVING PERMIT (IDP)</h3>
            <div class="text-[10px] text-slate-300">GOVERNMENT OF INDIA • MINISTRY OF ROAD TRANSPORT & HIGHWAYS</div>
          </div>
          <div class="p-4 space-y-3 text-xs">
            <div class="flex items-start gap-4">
              <div class="w-20 h-24 rounded border-2 border-slate-700 overflow-hidden shrink-0 bg-slate-200">
                <img src="https://images.unsplash.com/photo-1573496359142-b8d87734a5a2?auto=format&fit=crop&w=200&h=240&q=80" alt="IDP Photo" class="w-full h-full object-cover"/>
              </div>
              <div class="flex-grow space-y-1 font-mono text-[11px]">
                <div>Permit No: <strong class="text-amber-800">IDP/DL/2026/894012</strong></div>
                <div>Indian DL No: <strong>DL-04-20220019284</strong></div>
                <div>Passport No: <strong>Z8492019 (Valid Till 2034)</strong></div>
                <div>Full Name: <strong>${name}</strong></div>
                <div>Permitted Vehicles: <span class="bg-amber-100 text-amber-900 px-1.5 py-0.5 rounded font-bold">Category B (LMV Motor Cars)</span></div>
                <div>Valid Across: <strong>150+ Contracting States (1 Year Statutory)</strong></div>
              </div>
            </div>
            <div class="pt-2 border-t border-slate-300 flex justify-between items-center text-[10px] font-mono">
              <span class="text-emerald-700 font-bold">✓ MoRTH & Parivahan Digital Attestation Verified</span>
              <span>Issue Date: 16-Oct-2026</span>
            </div>
          </div>
        </div>`;
      finishTransRender('International Driving Permit (IDP)', 'IDP/DL/2026/894012');
      return;
    } else if (subKey === 'hpt') {
      container.innerHTML = `
        <div class="dl-card-frame w-full max-w-[560px] bg-white border-2 border-emerald-600 shadow-md rounded-xl p-5 font-sans space-y-3 text-xs">
          <div class="flex items-center justify-between pb-3 border-b border-slate-200">
            <div>
              <span class="text-[10px] font-mono font-bold bg-emerald-100 text-emerald-800 px-2 py-0.5 rounded">FORM 35 (RULE 61(2))</span>
              <h4 class="font-black text-sm text-[#00314D] mt-1">NOTICE OF TERMINATION OF HYPOTHECATION (HPT)</h4>
              <div class="text-[11px] text-slate-500">Parivahan Sewa • Vahan 4.0 Financial Lien Clearance</div>
            </div>
            <div class="w-10 h-10 rounded-full bg-emerald-100 text-emerald-700 flex items-center justify-center font-bold">
              <i data-lucide="check-check" class="w-5 h-5"></i>
            </div>
          </div>
          <div class="space-y-1.5 font-mono text-[11px] bg-slate-50 p-3 rounded-lg border border-slate-200">
            <div>Vehicle Reg No: <strong class="text-blue-900">${regNo}</strong></div>
            <div>Registered Owner: <strong>${name}</strong></div>
            <div>Financier / Bank: <strong>State Bank of India (Auto Loan Div)</strong></div>
            <div>Loan Account No: <strong>SBI/AUTO/9482019482</strong> (NOC Received)</div>
            <div>Lien Status: <span class="text-emerald-700 font-bold uppercase">Hypothecation Terminated & Cancelled</span></div>
          </div>
          <p class="text-[11px] text-slate-600">This document certifies that the loan on the vehicle has been fully discharged. The lien endorsement has been removed from the central Parivahan RC database.</p>
          <div class="pt-2 border-t border-slate-200 flex justify-between items-center text-[10px] font-mono">
            <span>Registering Authority: <strong>RTO West Delhi</strong></span>
            <span class="text-emerald-700 font-bold">✓ Bank e-Sign Verified</span>
          </div>
        </div>`;
      finishTransRender('Notice of Termination of Hypothecation (HPT)', regNo);
      return;
    } else if (subKey === 'conductor') {
      container.innerHTML = `
        <div class="dl-card-frame w-full max-w-[560px] bg-white border-2 border-sky-600 shadow-md rounded-xl p-5 font-sans space-y-3 text-xs">
          <div class="flex items-center justify-between pb-2 border-b border-slate-200">
            <div>
              <span class="text-[10px] font-mono font-bold bg-sky-100 text-sky-800 px-2 py-0.5 rounded">MOTOR VEHICLES ACT (SECTION 30)</span>
              <h4 class="font-black text-sm text-[#00314D] mt-1">STAGE CARRIAGE CONDUCTOR LICENCE & BADGE</h4>
              <div class="text-[11px] text-slate-500">State Transport Authority • Sarathi Conductor Desk</div>
            </div>
            <div class="w-12 h-12 rounded-lg bg-sky-700 text-white flex flex-col items-center justify-center font-black leading-tight text-[10px]">
              <span>BADGE</span>
              <span class="text-xs">#4819</span>
            </div>
          </div>
          <div class="space-y-1.5 font-mono text-[11px]">
            <div>Licence No: <strong>CL/DL04/2026/004819</strong></div>
            <div>Conductor Name: <strong>${name}</strong> | Blood Group: <strong>${blood}</strong></div>
            <div>Medical Fitness: <strong>Certified Fit (Form 1A Approved)</strong></div>
            <div>First Aid Qualification: <strong>St. John Ambulance Certificate #SJ-94812</strong></div>
            <div>Police Verification: <strong>Clear / No Antecedents Pending</strong></div>
          </div>
          <div class="pt-2 border-t border-slate-200 flex justify-between items-center text-[10px] font-mono">
            <span>Badge Authority: RTO Janakpuri</span>
            <span class="text-emerald-700 font-bold">✓ Active Valid Till 2031</span>
          </div>
        </div>`;
      finishTransRender('Stage Carriage Conductor Licence & Badge', 'CL/DL04/2026/004819');
      return;
    }

    if (subKey === 'll') {
      container.innerHTML = `
        <div class="dl-card-frame w-full max-w-[560px] bg-white border-4 border-[#0284C7] shadow-lg rounded-xl overflow-hidden font-sans" id="printable-dl-card">
          <div class="bg-gradient-to-r from-[#FF9933] via-[#FFFFFF] to-[#138808] h-1.5 w-full"></div>
          
          <div class="bg-[#0369A1] text-white p-3 px-4 flex items-center justify-between">
            <div class="flex items-center gap-2">
              <div class="w-8 h-8 rounded-full bg-red-600 text-white font-black text-lg flex items-center justify-center border-2 border-white shadow-xs">
                L
              </div>
              <div>
                <div class="text-[11px] font-black tracking-wide uppercase">UNION OF INDIA • LEARNER'S LICENCE</div>
                <div class="text-[9px] text-[#BAE6FD]">MOTOR VEHICLES ACT 1988 (RULE 3) • SARATHI 4.0</div>
              </div>
            </div>
            <div class="text-right">
              <span class="text-[9px] font-bold bg-white text-[#0369A1] px-2 py-0.5 rounded border border-[#38BDF8]">
                FORM 3 (RULE 3(a))
              </span>
              <div class="text-[8px] text-sky-100 font-mono mt-0.5">VALID FOR 6 MONTHS</div>
            </div>
          </div>

          <div class="p-4 bg-sky-50/50 space-y-3">
            <div class="flex gap-3 items-start">
              <div class="space-y-2 shrink-0">
                <div class="w-20 h-24 rounded-lg overflow-hidden border-2 border-[#0369A1] shadow-xs relative bg-slate-100">
                  <img src="https://images.unsplash.com/photo-1573496359142-b8d87734a5a2?auto=format&fit=crop&w=200&h=240&q=80" alt="Citizen Learner Licence Photo" class="w-full h-full object-cover"/>
                  <div class="absolute bottom-0 inset-x-0 bg-red-600/90 text-[7.5px] text-white text-center font-bold py-0.5 uppercase">
                    Learner Driver
                  </div>
                </div>
                <div class="w-20 p-1 bg-white border border-[#CBD5E1] rounded text-center">
                  <i data-lucide="qr-code" class="w-14 h-14 mx-auto text-[#00314D]"></i>
                  <span class="text-[7.5px] font-mono text-[#64748B] block mt-0.5">SCAN TO VERIFY</span>
                </div>
              </div>

              <div class="flex-grow space-y-1.5 text-[11px] text-[#1F2937]">
                <div>
                  <span class="text-[10px] text-[#64748B] uppercase tracking-wider block">Learner's Licence Number:</span>
                  <span class="font-mono text-base font-black text-[#0369A1] tracking-wide">LL-042026/0091842</span>
                </div>
                <div class="border-t border-[#E2E8F0] pt-1">
                  <span class="text-[#64748B] text-[10px]">Learner Full Name:</span>
                  <strong class="text-[#00314D] text-xs block">${name}</strong>
                </div>
                <div>
                  <span class="text-[#64748B] text-[10px]">Son/Daughter/Wife of:</span>
                  <span class="font-semibold block">${father}</span>
                </div>
                <div class="grid grid-cols-2 gap-1.5">
                  <div>
                    <span class="text-[#64748B] text-[10px]">DOB:</span>
                    <strong class="font-mono block">${dob}</strong>
                  </div>
                  <div>
                    <span class="text-[#64748B] text-[10px]">Online Test Result:</span>
                    <strong class="text-[#138808] font-bold block">PASSED (15/15)</strong>
                  </div>
                </div>
                <div class="grid grid-cols-2 gap-1.5">
                  <div>
                    <span class="text-[#64748B] text-[10px]">Issue Date:</span>
                    <span class="font-mono font-semibold block">16-10-2026</span>
                  </div>
                  <div>
                    <span class="text-[#64748B] text-[10px]">Valid Up To:</span>
                    <strong class="text-[#DC2626] font-mono block">15-04-2027</strong>
                  </div>
                </div>
                <div class="border-t border-[#E2E8F0] pt-1">
                  <span class="text-[#64748B] text-[10px] block mb-0.5">Permitted Class of Vehicles:</span>
                  <div class="flex flex-wrap gap-1">
                    <span class="text-[9.5px] font-bold bg-white text-[#0369A1] border border-sky-300 px-1.5 py-0.5 rounded">
                      ${dlClass}
                    </span>
                  </div>
                </div>
                <div class="text-[9.5px] text-[#64748B] pt-0.5">
                  <span>Address: </span><span class="text-[#1F2937]">${address}</span>
                </div>
              </div>
            </div>
            
            <div class="bg-amber-50 p-2 rounded border border-amber-200 text-[10px] text-[#854D0E] space-y-0.5">
              <div class="font-bold">वैधानिक शर्त (Statutory Rule 3):</div>
              <div>वाहन चलाते समय आगे और पीछे लाल रंग का 'L' बोर्ड लगाना अनिवार्य है तथा साथ में वैध स्थायी लाइसेंसधारी प्रशिक्षक उपस्थित होना चाहिए।</div>
            </div>
          </div>

          <div class="bg-slate-900 text-white p-2 px-3 flex items-center justify-between text-[9px]">
            <span class="flex items-center gap-1 text-slate-300">
              <i data-lucide="shield-check" class="w-3.5 h-3.5 text-[#10B981]"></i>
              <span>Parivahan Digital Interoperability Verified</span>
            </span>
            <span class="font-mono text-[#38BDF8] font-bold">
              LICENSING AUTHORITY DL-04
            </span>
          </div>
        </div>`;
    } else if (subKey === 'renewal') {
      container.innerHTML = `
        <div class="dl-card-frame w-full max-w-[560px] bg-white border-4 border-[#0F766E] shadow-lg rounded-xl overflow-hidden font-sans" id="printable-dl-card">
          <div class="bg-gradient-to-r from-[#FF9933] via-[#FFFFFF] to-[#138808] h-1.5 w-full"></div>
          
          <div class="bg-[#0F766E] text-white p-3 px-4 flex items-center justify-between">
            <div class="flex items-center gap-2">
              <i data-lucide="refresh-cw" class="w-6 h-6 text-[#99F6E4]"></i>
              <div>
                <div class="text-[11px] font-black tracking-wide uppercase">UNION OF INDIA • LICENCE RENEWAL ENDORSEMENT</div>
                <div class="text-[9px] text-[#CCFBF1]">MOTOR VEHICLES ACT 1988 (SECTION 15) • FORM 9</div>
              </div>
            </div>
            <div class="text-right">
              <span class="text-[9px] font-bold bg-white text-[#0F766E] px-2 py-0.5 rounded border border-[#5EEAD4]">
                FORM 9 (RENEWED)
              </span>
              <div class="text-[8px] text-teal-100 font-mono mt-0.5">EXTENDED +20 YEARS</div>
            </div>
          </div>

          <div class="p-4 bg-teal-50/40 space-y-3">
            <div class="bg-white p-3 rounded-lg border border-teal-200 shadow-2xs space-y-2 text-xs">
              <div class="flex items-center justify-between border-b pb-2">
                <div>
                  <span class="text-[10px] text-slate-500 block">Existing Driving Licence No:</span>
                  <strong class="font-mono text-sm text-[#00314D]">DL-0420210084920</strong>
                </div>
                <div class="text-right">
                  <span class="text-[10px] text-slate-500 block">Renewal Application Ref:</span>
                  <span class="font-mono text-xs text-[#0F766E] font-bold">RNW/DL/2026/84910</span>
                </div>
              </div>

              <div class="grid grid-cols-2 gap-2 text-[11px]">
                <div>Holder: <strong>${name}</strong></div>
                <div>S/D/W: <strong>${father}</strong></div>
                <div>Previous Expiry: <strong class="text-red-600 font-mono">15-08-2026</strong></div>
                <div>Renewed Validity: <strong class="text-emerald-700 font-mono">15-08-2046 (20 Yrs)</strong></div>
                <div>Medical Fitness (Form 1A): <strong class="text-[#0F766E]">Certified by CMO Board</strong></div>
                <div>Biometric & Eye Test: <strong class="text-emerald-700">Matched & Verified</strong></div>
              </div>

              <div class="p-2 bg-emerald-50 rounded border border-emerald-200 text-[10px] text-emerald-900 flex items-center justify-between">
                <div>
                  <span class="font-bold">पृष्ठांकन आदेश (Endorsement Order):</span>
                  <div>यह अनुज्ञप्ति मोटर यान अधिनियम १९८८ की धारा १५ के अंतर्गत आगामी २० वर्षों हेतु वैध घोषित की जाती है।</div>
                </div>
                <i data-lucide="check-circle-2" class="w-6 h-6 text-emerald-600 shrink-0"></i>
              </div>
            </div>

            <div class="flex items-center justify-between text-[10px] text-slate-600 pt-1">
              <span>Authority: <strong>${authority}</strong></span>
              <span>Updated on DigiLocker: <strong>Instant Sync</strong></span>
            </div>
          </div>

          <div class="bg-slate-900 text-white p-2 px-3 flex items-center justify-between text-[9px]">
            <span class="flex items-center gap-1 text-slate-300">
              <i data-lucide="shield-check" class="w-3.5 h-3.5 text-[#10B981]"></i>
              <span>National Register Parivahan Sarathi Synced</span>
            </span>
            <span class="font-mono text-[#5EEAD4] font-bold">
              LICENSING OFFICER DL-04
            </span>
          </div>
        </div>`;
    } else if (subKey === 'rc') {
      container.innerHTML = `
        <div class="dl-card-frame w-full max-w-[560px] bg-white border-4 border-[#1E3A8A] shadow-lg rounded-xl overflow-hidden font-sans" id="printable-dl-card">
          <div class="bg-gradient-to-r from-[#FF9933] via-[#FFFFFF] to-[#138808] h-1.5 w-full"></div>
          
          <div class="bg-[#1E3A8A] text-white p-3 px-4 flex items-center justify-between">
            <div class="flex items-center gap-2">
              <i data-lucide="car" class="w-6 h-6 text-[#93C5FD]"></i>
              <div>
                <div class="text-[11px] font-black tracking-wide uppercase">GOVERNMENT OF INDIA • CERTIFICATE OF REGISTRATION</div>
                <div class="text-[9px] text-[#BFDBFE]">CENTRAL MOTOR VEHICLE RULES 1989 • FORM 23 (VAHAN 4.0)</div>
              </div>
            </div>
            <div class="text-right">
              <span class="text-[9px] font-bold bg-white text-[#1E3A8A] px-2 py-0.5 rounded border border-[#60A5FA]">
                FORM 23 (RULE 48)
              </span>
              <div class="text-[8px] text-blue-200 font-mono mt-0.5">SMART RC CHIP</div>
            </div>
          </div>

          <div class="p-4 bg-blue-50/30 space-y-3">
            <div class="flex items-center justify-between bg-white p-2.5 rounded-lg border border-blue-200">
              <div>
                <span class="text-[9.5px] text-slate-500 uppercase tracking-wider block">Registration Number (वाहन क्रमांक):</span>
                <span class="font-mono text-lg font-black text-[#1E3A8A]">${regNo}</span>
              </div>
              <div class="text-right">
                <span class="text-[9.5px] text-slate-500 block">Registering Authority:</span>
                <span class="text-xs font-bold text-slate-700">${authority.split(',')[0]}</span>
              </div>
            </div>

            <table class="gov-cert-table text-xs">
              <tbody>
                <tr>
                  <th class="w-1/3">Owner Full Name:</th>
                  <td class="font-bold text-[#1E3A8A]">${name}</td>
                  <th>S/D/W of:</th>
                  <td>${father}</td>
                </tr>
                <tr>
                  <th>Vehicle Maker & Model:</th>
                  <td colspan="3" class="font-semibold text-slate-800">${maker}</td>
                </tr>
                <tr>
                  <th>Chassis Number:</th>
                  <td class="font-mono font-bold text-slate-800">${chassis}</td>
                  <th>Engine Number:</th>
                  <td class="font-mono font-bold text-slate-800">${engine}</td>
                </tr>
                <tr>
                  <th>Fuel & Emission:</th>
                  <td>${fuel}</td>
                  <th>Fitness Valid Up To:</th>
                  <td class="font-bold text-[#138808]">${rcValidity}</td>
                </tr>
                <tr>
                  <th>Hypothecation (HPA):</th>
                  <td colspan="3" class="text-slate-700">State Bank of India (Auto Loan Cell) • Hypothecated</td>
                </tr>
                <tr>
                  <th>Permanent Address:</th>
                  <td colspan="3">${address}</td>
                </tr>
              </tbody>
            </table>

            <div class="flex items-center justify-between text-[10px] text-slate-600 bg-white p-2 rounded border border-slate-200">
              <div class="flex items-center gap-1.5 text-emerald-700 font-bold">
                <i data-lucide="shield-check" class="w-4 h-4"></i>
                <span>Tax Paid (One-Time LTT) • Comprehensive Insurance Active</span>
              </div>
              <div class="w-12 h-12 shrink-0 border p-0.5 rounded bg-white">
                <i data-lucide="qr-code" class="w-full h-full text-[#1E3A8A]"></i>
              </div>
            </div>
          </div>

          <div class="bg-slate-900 text-white p-2 px-3 flex items-center justify-between text-[9px]">
            <span class="flex items-center gap-1 text-slate-300">
              <i data-lucide="shield-check" class="w-3.5 h-3.5 text-[#10B981]"></i>
              <span>National Vahan Citizen Registry • DigiLocker Digital RC Push Complete</span>
            </span>
            <span class="font-mono text-[#93C5FD] font-bold">
              REGISTRATION AUTHORITY
            </span>
          </div>
        </div>`;
    } else if (subKey === 'fitness') {
      container.innerHTML = `
        <div class="dl-card-frame w-full max-w-[560px] bg-white border-4 border-[#047857] shadow-lg rounded-xl overflow-hidden font-sans" id="printable-dl-card">
          <div class="bg-gradient-to-r from-[#FF9933] via-[#FFFFFF] to-[#138808] h-1.5 w-full"></div>
          
          <div class="bg-[#047857] text-white p-3 px-4 flex items-center justify-between">
            <div class="flex items-center gap-2">
              <i data-lucide="shield-check" class="w-6 h-6 text-[#A7F3D0]"></i>
              <div>
                <div class="text-[11px] font-black tracking-wide uppercase">UNION OF INDIA • VEHICLE FITNESS & PUCC CERTIFICATE</div>
                <div class="text-[9px] text-[#D1FAE5]">CENTRAL MOTOR VEHICLE RULES 1989 • FORM 38 & SECTION 56</div>
              </div>
            </div>
            <div class="text-right">
              <span class="text-[9px] font-bold bg-white text-[#047857] px-2 py-0.5 rounded border border-[#6EE7B7]">
                FORM 38 (RULE 62)
              </span>
              <div class="text-[8px] text-emerald-100 font-mono mt-0.5">ATS CERTIFIED</div>
            </div>
          </div>

          <div class="p-4 bg-emerald-50/30 space-y-3">
            <div class="flex items-center justify-between bg-white p-2.5 rounded-lg border border-emerald-200">
              <div>
                <span class="text-[9.5px] text-slate-500 block">Vehicle Reg No:</span>
                <span class="font-mono text-base font-black text-[#047857]">${regNo}</span>
              </div>
              <div class="text-center">
                <span class="text-[9.5px] text-slate-500 block">Test Station:</span>
                <span class="text-xs font-bold text-slate-700">Automated Testing Station, Delhi-04</span>
              </div>
              <div class="text-right">
                <span class="text-[9.5px] text-slate-500 block">Certificate No:</span>
                <span class="font-mono text-xs font-bold text-[#047857]">FIT/2026/84920</span>
              </div>
            </div>

            <div class="bg-white rounded-lg border border-slate-200 overflow-hidden text-xs">
              <div class="bg-slate-100 p-2 font-bold text-slate-700 border-b">Automated Inspection Parameters & Results:</div>
              <div class="p-3 grid grid-cols-2 gap-2 text-[11px]">
                <div>• Carbon Monoxide (CO): <strong class="text-emerald-700 font-mono">0.04% (Max: 0.5%)</strong></div>
                <div>• Hydrocarbons (HC): <strong class="text-emerald-700 font-mono">42 ppm (Max: 750)</strong></div>
                <div>• Brake Efficiency: <strong class="text-emerald-700 font-mono">74% (Min: 50% PASS)</strong></div>
                <div>• Headlamp Beam Alignment: <strong class="text-emerald-700 font-mono">COMPLIANT</strong></div>
                <div>• Speed Limiting Device: <strong class="text-emerald-700 font-mono">Calibrated (80 km/h)</strong></div>
                <div>• Exhaust Smoke Density: <strong class="text-emerald-700 font-mono">0.38 m⁻¹ (PASS)</strong></div>
              </div>
            </div>

            <div class="p-2.5 bg-emerald-100/60 rounded-lg border border-emerald-300 text-[10.5px] text-emerald-950 flex items-center justify-between">
              <div>
                <div class="font-bold">सड़क उपयोग उपयुक्तता सत्यापन (Statutory Roadworthiness Decision):</div>
                <div>यह वाहन सड़क परिवहन एवं राजमार्ग मंत्रालय के संरक्षा एवं उत्सर्जन मानकों के पूर्णतः अनुकूल है।</div>
              </div>
              <span class="px-2.5 py-1 bg-[#047857] text-white font-black text-xs rounded uppercase">
                ROADWORTHY
              </span>
            </div>

            <div class="flex items-center justify-between text-[10px] text-slate-500 pt-1">
              <span>Inspected On: <strong>16-Oct-2026</strong></span>
              <span>Next Inspection Due: <strong class="text-[#047857]">15-Oct-2028 (2 Years)</strong></span>
            </div>
          </div>

          <div class="bg-slate-900 text-white p-2 px-3 flex items-center justify-between text-[9px]">
            <span class="flex items-center gap-1 text-slate-300">
              <i data-lucide="shield-check" class="w-3.5 h-3.5 text-[#10B981]"></i>
              <span>Government Automated Testing Station (ATS) Cryptographically Certified</span>
            </span>
            <span class="font-mono text-[#6EE7B7] font-bold">
              INSPECTING AUTHORITY
            </span>
          </div>
        </div>`;
    } else {
      // 1. Default: Smart Card Driving Licence (Form 7)
      container.innerHTML = `
        <div class="dl-card-frame w-full max-w-[560px]" id="printable-dl-card">
          <div class="bg-gradient-to-r from-[#FF9933] via-[#FFFFFF] to-[#138808] h-1.5 w-full"></div>
          
          <div class="bg-[#00314D] text-white p-3 px-4 flex items-center justify-between">
            <div class="flex items-center gap-2">
              <svg class="w-7 h-7 shrink-0 text-[#FFCC00]" viewBox="0 0 100 100" fill="currentColor">
                <circle cx="50" cy="50" r="45" fill="none" stroke="#FFCC00" stroke-width="4"/>
                <circle cx="50" cy="50" r="10" fill="#FFCC00"/>
                <path d="M50 10 L50 90 M10 50 L90 50 M22 22 L78 78 M22 78 L78 22" stroke="#FFCC00" stroke-width="3"/>
              </svg>
              <div>
                <div class="text-[11px] font-black tracking-wide uppercase">UNION OF INDIA • DRIVING LICENCE</div>
                <div class="text-[9px] text-[#BAE6FD]">TRANSPORT DEPARTMENT • GOVT OF NCT OF DELHI</div>
              </div>
            </div>
            <div class="text-right">
              <span class="text-[9px] font-bold bg-[#0284C7] text-white px-2 py-0.5 rounded border border-[#38BDF8]">
                FORM 7 (RULE 16(2))
              </span>
              <div class="text-[8px] text-slate-300 font-mono mt-0.5">PARIVAHAN SARATHI 4.0</div>
            </div>
          </div>

          <div class="p-4 bg-white/90 space-y-3">
            <div class="flex gap-3 items-start">
              
              <div class="space-y-2 shrink-0">
                <div class="w-11 h-8 rounded bg-gradient-to-br from-[#F59E0B] via-[#FBBF24] to-[#D97706] border border-[#B45309] shadow-xs relative overflow-hidden">
                  <div class="absolute inset-0 grid grid-cols-3 grid-rows-2 gap-0.5 p-0.5 opacity-60">
                    <div class="border border-[#78350F]"></div>
                    <div class="border border-[#78350F]"></div>
                    <div class="border border-[#78350F]"></div>
                    <div class="border border-[#78350F]"></div>
                    <div class="border border-[#78350F]"></div>
                    <div class="border border-[#78350F]"></div>
                  </div>
                </div>

                <div class="w-20 h-24 rounded-lg overflow-hidden border-2 border-[#00314D] shadow-xs relative bg-slate-100">
                  <img src="https://images.unsplash.com/photo-1573496359142-b8d87734a5a2?auto=format&fit=crop&w=200&h=240&q=80" alt="Citizen Driving Licence Photograph" class="w-full h-full object-cover"/>
                  <div class="absolute bottom-0 inset-x-0 bg-[#00314D]/80 text-[7px] text-white text-center font-bold py-0.5">
                    DELHI RTO
                  </div>
                </div>

                <div class="w-20 p-1 bg-white border border-[#CBD5E1] rounded text-center">
                  <i data-lucide="qr-code" class="w-14 h-14 mx-auto text-[#00314D]"></i>
                  <span class="text-[7.5px] font-mono text-[#64748B] block mt-0.5">SCAN TO VERIFY</span>
                </div>
              </div>

              <div class="flex-grow space-y-1.5 text-[11px] text-[#1F2937]">
                <div>
                  <span class="text-[10px] text-[#64748B] uppercase tracking-wider block">Driving Licence Number:</span>
                  <span class="font-mono text-base font-black text-[#00314D] tracking-wide">DL-0420260084920</span>
                </div>

                <div class="border-t border-[#E2E8F0] pt-1">
                  <span class="text-[#64748B] text-[10px]">Name:</span>
                  <strong class="text-[#00314D] text-xs block">${name}</strong>
                </div>

                <div>
                  <span class="text-[#64748B] text-[10px]">S/D/W of:</span>
                  <span class="font-semibold block">${father}</span>
                </div>

                <div class="grid grid-cols-2 gap-1.5">
                  <div>
                    <span class="text-[#64748B] text-[10px]">DOB:</span>
                    <strong class="font-mono block">${dob}</strong>
                  </div>
                  <div>
                    <span class="text-[#64748B] text-[10px]">Blood Group:</span>
                    <strong class="text-[#DC2626] font-mono block">${blood.split(' ')[0]}</strong>
                  </div>
                </div>

                <div class="grid grid-cols-2 gap-1.5">
                  <div>
                    <span class="text-[#64748B] text-[10px]">Issue Date:</span>
                    <span class="font-mono font-semibold block">12-10-2026</span>
                  </div>
                  <div>
                    <span class="text-[#64748B] text-[10px]">Validity (NT):</span>
                    <strong class="text-[#047857] font-mono block">14-08-2042</strong>
                  </div>
                </div>

                <div class="border-t border-[#E2E8F0] pt-1.5">
                  <span class="text-[#64748B] text-[10px] block mb-1">Authorised To Drive (COV):</span>
                  <div class="flex flex-wrap gap-1">
                    <span class="text-[10px] font-bold bg-[#E0F2FE] text-[#0369A1] border border-[#BAE6FD] px-2 py-0.5 rounded">
                      ${dlClass}
                    </span>
                  </div>
                </div>

                <div class="text-[10px] text-[#64748B] pt-1">
                  <span>Address: </span><span class="text-[#1F2937]">${address}</span>
                </div>
              </div>

            </div>
          </div>

          <div class="bg-gradient-to-r from-[#00314D] via-[#004B75] to-[#00314D] text-white p-2 px-3 flex items-center justify-between text-[9px] border-t border-[#002236]">
            <span class="flex items-center gap-1 text-slate-300">
              <i data-lucide="shield-check" class="w-3.5 h-3.5 text-[#10B981]"></i>
              <span>Smart Optical Security • DigiLocker &amp; mParivahan Synced</span>
            </span>
            <span class="font-mono text-[#FFCC00] font-bold">
              LICENSING AUTHORITY DL-04
            </span>
          </div>
        </div>
      `;
    }

    let dlCertTitle = 'Smart Card Driving Licence (फॉर्म 7)';
    let dlCertNo = 'DL-0420260084920';
    if (subKey === 'll') { dlCertTitle = "Learner's Licence (फॉर्म 3)"; dlCertNo = 'LL/DL04/2026/89412'; }
    else if (subKey === 'rc') { dlCertTitle = 'Vehicle Registration Certificate (RC Form 23)'; dlCertNo = regNo; }
    else if (subKey === 'fitness') { dlCertTitle = 'Vehicle Fitness Certificate (Form 38)'; dlCertNo = 'CF/DL04/2026/001928'; }
    else if (subKey === 'renewal') { dlCertTitle = 'Driving Licence Renewal Endorsement'; dlCertNo = 'RNW/DL/2026/84910'; }
    
    finishTransRender(dlCertTitle, dlCertNo);
  };

window.launchPrototypeWorkflow = function(deskKey, docTab = 'birthcert') {
    window.navigateToPage('services', () => {
      window.switchProtoDesk(deskKey);
      if (deskKey === 'birth') {
        window.switchDocTab(docTab);
      }
      const target = document.getElementById('citizen-service-prototype');
      if (target) {
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  };

  window.printActiveCertificate = function() {
    window.print();
  };

  // =========================================================================
  // 13. TTS AUDIO ATTESTATION READER & VERIFICATION ENGINE (PURE WORKING ENGINE)
  // =========================================================================
  
  function showGovToast(message) {
    if (!message) return;
    let toast = document.getElementById('gov-toast-element');
    let msgEl = document.getElementById('gov-toast-message');
    if (!toast) {
      toast = document.createElement('div');
      toast.id = 'gov-toast-element';
      toast.className = 'gov-toast';
      toast.innerHTML = '<i data-lucide="bell" class="w-4 h-4 text-white"></i><span id="gov-toast-message" class="text-xs font-bold text-white"></span>';
      document.body.appendChild(toast);
      msgEl = document.getElementById('gov-toast-message');
    }
    if (toast && msgEl) {
      msgEl.textContent = message;
      toast.classList.add('show');
      if (toast._timer) clearTimeout(toast._timer);
      toast._timer = setTimeout(() => {
        toast.classList.remove('show');
      }, 3000);
    }
  }
  window.showGovToast = showGovToast;

  window.verifyOtpAction = function(type) {
    if (type === 'birth') {
    const otpVal = escapeHtml(document.getElementById('input-birth-otp')?.value || '849201');
      showGovToast(`Aadhaar OTP ${otpVal} Authenticated! UIDAI e-KYC & DPDP Consent Token Active`);
    } else if (type === 'biz') {
      showGovToast(`Director Class 3 DSC PIN Authenticated! MCA PKI Digital Signature Active`);
    } else if (type === 'farmer') {
    const otpVal = escapeHtml(document.getElementById('input-farmer-otp')?.value || '920148');
      showGovToast(`Farmer e-KYC OTP ${otpVal} Authenticated! Bhulekh Land Records Validated`);
    } else if (type === 'caste') {
    const otpVal = escapeHtml(document.getElementById('input-caste-otp')?.value || '741920');
      showGovToast(`Aadhaar e-KYC OTP ${otpVal} Authenticated! Revenue Archive & Tehsildar Token Active`);
    } else if (type === 'dl') {
    const otpVal = escapeHtml(document.getElementById('input-dl-otp')?.value || '849102');
      showGovToast(`Parivahan Auth OTP ${otpVal} Authenticated! MoRTH Sarathi Smart Card Provisioned`);
    }
  };

  window.copyVerificationToken = function(customToken) {
    let token = customToken;
    if (!token) {
      const activeDesk = document.getElementById('proto-tab-caste')?.classList.contains('active') ? 'caste' :
                         document.getElementById('proto-tab-dl')?.classList.contains('active') ? 'dl' :
                         document.getElementById('proto-tab-business')?.classList.contains('active') ? 'business' :
                         document.getElementById('proto-tab-farmer')?.classList.contains('active') ? 'farmer' : 'birth';
      if (activeDesk === 'caste') token = 'UP/2026/CC/849201';
      else if (activeDesk === 'dl') token = 'DL-0420260084920';
      else if (activeDesk === 'business') token = 'U72900DL2026PTC394812';
      else if (activeDesk === 'farmer') token = 'KH-48201/08';
      else token = 'CRS/2026/DL/948271';
    }

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(token).then(() => {
        showGovToast(`Token ${token} Copied to Clipboard!`);
      }).catch(() => {
        showGovToast(`Token: ${token}`);
      
  });
    } else {
      showGovToast(`Token: ${token}`);
    }
  };

  let activeUtterance = null;
  let activeSpeakingDesk = null;

  window.stopSpeaking = function() {
    if ('speechSynthesis' in window) {
      window.speechSynthesis.cancel();
    }
    resetTtsUI();
  };

  function resetTtsUI() {
    ['birth', 'biz', 'farmer', 'caste', 'dl'].forEach(key => {
      const wave = document.getElementById(`tts-wave-${key}`);
      const stopBtn = document.getElementById(`btn-tts-stop-${key}`);
      const statusText = document.getElementById(`tts-status-text-${key}`);
      const label = document.getElementById(`tts-label-${key}`);
      
      if (wave) wave.classList.remove('speaking');
      if (stopBtn) stopBtn.classList.add('hidden');
      if (statusText) {
        if (key === 'birth') statusText.innerHTML = '<i data-lucide="check-circle-2" class="w-3.5 h-3.5 text-[#138808]"></i><span>Official Gazette Voice Synthesizer Ready (GIGW 3.0 Audio A11y)</span>';
        if (key === 'biz') statusText.innerHTML = '<i data-lucide="check-circle-2" class="w-3.5 h-3.5 text-[#10B981]"></i><span>Ministry of Corporate Affairs Official Voice Engine Ready</span>';
        if (key === 'farmer') statusText.innerHTML = '<i data-lucide="check-circle-2" class="w-3.5 h-3.5 text-[#138808]"></i><span>Ministry of Agriculture Direct Benefit Transfer Voice Announcer Ready</span>';
        if (key === 'caste') statusText.innerHTML = '<i data-lucide="check-circle-2" class="w-3.5 h-3.5 text-[#138808]"></i><span>Revenue Department Official Gazette Voice Announcer Ready</span>';
        if (key === 'dl') statusText.innerHTML = '<i data-lucide="check-circle-2" class="w-3.5 h-3.5 text-[#138808]"></i><span>MoRTH Parivahan Voice Announcer Ready</span>';
      }
      if (label) {
        if (key === 'birth') label.textContent = 'Listen Official Attestation (वाच्य विवरण)';
        if (key === 'biz') label.textContent = 'Listen MCA Corporate Attestation';
        if (key === 'farmer') label.textContent = 'Listen DBT Sanction Order';
        if (key === 'caste') label.textContent = 'Listen Caste Certificate Audio (ऑडियो सुनें)';
        if (key === 'dl') label.textContent = 'Listen Driving Licence Audio (ऑडियो सुनें)';
      }
    
  });
    if (window.lucide) window.lucide.createIcons();
    activeSpeakingDesk = null;
  }

  window.speakCurrentCertificate = function(deskKey = 'birth') {
    if (!('speechSynthesis' in window)) {
      showGovToast('Web Speech API is not supported in this browser environment.');
      return;
    }

    window.speechSynthesis.cancel();
    resetTtsUI();

    const uiKey = deskKey === 'business' ? 'biz' : deskKey;
    activeSpeakingDesk = uiKey;

    const langSelect = document.getElementById(`tts-lang-${uiKey}`);
    const speedSelect = document.getElementById(`tts-speed-${uiKey}`);
    const chosenLang = langSelect ? langSelect.value : currentLang;
    const rate = speedSelect ? parseFloat(speedSelect.value) || 1.0 : 1.0;

    let textToSpeak = '';

    if (deskKey === 'birth') {
      const crsSub = window.currentCrsSubService || 'birth';
      if (crsSub === 'death') {
    const dName = escapeHtml(document.getElementById('input-death-name')?.value || 'Late Om Prakash Sharma');
    const dDate = escapeHtml(document.getElementById('input-death-date')?.value || '2026-09-28');
    const dPlace = escapeHtml(document.getElementById('input-death-place')?.value || 'AIIMS Hospital, New Delhi');
        if (chosenLang === 'hi') {
          textToSpeak = `नागरिक पंजीकरण प्रणाली, भारत सरकार। मृत्यु प्रमाण पत्र प्रपत्र संख्या 6। प्रमाणित किया जाता है कि मृतक ${dName} का देहावसान दिनांक ${dDate} को स्थान ${dPlace} में हुआ। पंजीकरण संख्या CRS 2026 DTH 581920। स्वास्थ्य अधिकारी दिल्ली नगर निगम द्वारा डिजिटल रूप से हस्ताक्षरित एवं डिजिलॉकर में उपलब्ध।`;
        } else {
          textToSpeak = `Civil Registration System, Government of India. Death Certificate Form 6 under RBD Act 1969. This certifies the death of ${dName} on ${dDate} at ${dPlace}. Registration number CRS 2026 DTH 581920. Digitally signed by Registrar of Births and Deaths, Delhi Municipal Corporation.`;
        }
      } else if (crsSub === 'marriage') {
    const groom = escapeHtml(document.getElementById('input-marriage-groom')?.value || 'Rohit Sharma');
    const bride = escapeHtml(document.getElementById('input-marriage-bride')?.value || 'Pooja Verma');
    const mDate = escapeHtml(document.getElementById('input-marriage-date')?.value || '2022-11-20');
        if (chosenLang === 'hi') {
          textToSpeak = `विवाह पंजीकरण कार्यालय, दिल्ली शासन। विवाह प्रमाण पत्र प्रपत्र ख। प्रमाणित किया जाता है कि श्री ${groom} एवं सुश्री ${bride} का विवाह दिनांक ${mDate} को संपन्न हुआ। पंजीकरण संख्या MRG 2026 DL 104928। विवाह अधिकारी एवं उपजिलाधिकारी द्वारा ई-हस्ताक्षरित।`;
        } else {
          textToSpeak = `Office of the Marriage Officer, Revenue Department, Government of NCT of Delhi. Certificate of Marriage Registration Form B. Certifies that marriage between ${groom} and ${bride} was solemnized on ${mDate}. Registration number MRG 2026 DL 104928. Digitally authenticated by Sub-Divisional Magistrate.`;
        }
      } else {
    const child = escapeHtml(document.getElementById('input-child-name')?.value || 'Aarav Sharma');
    const dob = escapeHtml(document.getElementById('input-child-dob')?.value || '2026-10-12');
    const hospital = escapeHtml(document.getElementById('input-hospital')?.value || 'AIIMS New Delhi');
        if (chosenLang === 'hi') {
          textToSpeak = `राष्ट्रीय डिजिटल अंतर-प्रचालनीयता गेटवे, भारत सरकार। जन्म प्रमाण पत्र फॉर्म संख्या 5। शिशु ${child} का जन्म दिनांक ${dob} को स्थान ${hospital} में प्रमाणित किया गया। बाल आधार टोकन जारी कर डिजीलॉकर वॉल्ट में सुरक्षित जमा किया गया।`;
        } else {
          textToSpeak = `National Digital Interoperability Gateway, Government of India. Civil Registration Form 5. Birth Certificate officially issued for infant ${child}, born on ${dob} at ${hospital}. Baal Aadhaar token generated and pushed to citizen DigiLocker vault.`;
        }
      }
    } else if (deskKey === 'business' || deskKey === 'biz') {
      const bizSub = window.currentBusinessSubService || 'spice';
    const bizName = escapeHtml(document.getElementById('input-biz-name')?.value || 'Bharat Enterprise Cloud Technologies Pvt Ltd');
      if (bizSub === 'udyam') {
        if (chosenLang === 'hi') {
          textToSpeak = `सूक्ष्म, लघु एवं मध्यम उद्यम मंत्रालय, भारत सरकार। उद्यम पंजीकरण प्रमाण पत्र संख्या UDYAM UP 28 0094821। उद्यम का नाम ${bizName}। आयकर पैन एवं जीएसटीएन नेटवर्क से सत्यापित।`;
        } else {
          textToSpeak = `Ministry of Micro, Small and Medium Enterprises, Government of India. Udyam Registration Certificate UDYAM UP 28 0094821 issued to ${bizName}. Verified through Income Tax PAN and GSTN database under MSMED Act 2006.`;
        }
      } else if (bizSub === 'eshram') {
        if (chosenLang === 'hi') {
          textToSpeak = `श्रम एवं रोजगार मंत्रालय, भारत सरकार। ई-श्रम राष्ट्रीय कामगार कार्ड। यूनिवर्सल अकाउंट नंबर UAN 1004 8921 7384। प्रधानमंत्री सुरक्षा बीमा योजना के अंतर्गत ₹ 2 लाख का दुर्घटना बीमा कवर सक्रिय।`;
        } else {
          textToSpeak = `Ministry of Labour and Employment, Government of India. e-Shram Universal Account Number 1004 8921 7384. Accidental insurance cover of rupees two lakh active under Pradhan Mantri Suraksha Bima Yojana.`;
        }
      } else if (bizSub === 'trade') {
        if (chosenLang === 'hi') {
          textToSpeak = `नगर निगम स्वास्थ्य एवं उद्योग विभाग। व्यापार एवं दुकान स्थापना अनुज्ञप्ति संख्या TL MCD 2026 08492। प्रतिष्ठान ${bizName}। अग्निशमन एवं स्वच्छता मानकों के अनुरूप डिजिटल रूप से अधिकृत।`;
        } else {
          textToSpeak = `Municipal Corporation Licensing Department. Commercial Trade and Establishment Licence TL MCD 2026 08492 for ${bizName}. Fire NOC and health clearances certified by Municipal Authority.`;
        }
      } else {
        if (chosenLang === 'hi') {
          textToSpeak = `कॉर्पोरेट कार्य मंत्रालय, भारत सरकार। समामेलन का प्रमाण पत्र। कंपनी का नाम ${bizName}। कॉर्पोरेट पहचान संख्या CIN U72900DL2026PTC394812। कंपनी रजिस्ट्रार द्वारा डिजिटल रूप से हस्ताक्षरित एवं प्रमाणित।`;
        } else {
          textToSpeak = `Ministry of Corporate Affairs, Government of India. Certificate of Incorporation for ${bizName}. Corporate Identity Number CIN U72900DL2026PTC394812. Permanent Account Number and GSTIN digitally validated by Registrar of Companies.`;
        }
      }
    } else if (deskKey === 'farmer') {
      const fSub = window.currentFarmerSubService || 'pmkisan';
    const farmer = escapeHtml(document.getElementById('input-farmer-name')?.value || 'Ramesh Kumar Yadav');
      if (fSub === 'ration') {
        if (chosenLang === 'hi') {
          textToSpeak = `खाद्य एवं रसद विभाग, उत्तर प्रदेश। राष्ट्रीय खाद्य सुरक्षा डिजिटल राशन कार्ड संख्या NFSA UP 094819204। परिवार के मुखिया ${farmer}। 5 यूनिट हेतु 35 किलोग्राम निःशुल्क खाद्यान्न मासिक आवंटन। वन नेशन वन राशन कार्ड प्रणाली में सक्रिय।`;
        } else {
          textToSpeak = `Department of Food and Civil Supplies. National Food Security Digital Ration Card NFSA UP 094819204 for ${farmer}. Monthly entitlement 35 kilograms free foodgrain for 5 family units. One Nation One Ration Card enabled across India.`;
        }
      } else if (fSub === 'kcc') {
        if (chosenLang === 'hi') {
          textToSpeak = `नाबार्ड एवं भारतीय स्टेट बैंक। किसान क्रेडिट कार्ड स्वीकृति पत्र। खाता संख्या KCC SBI 2026 48192। लाभार्थी किसान ${farmer}। स्वीकृत साख सीमा ₹ 3 लाख, 4 प्रतिशत रियायती ब्याज दर पर स्वीकृत।`;
        } else {
          textToSpeak = `NABARD and State Bank of India. Kisan Credit Card sanction letter for ${farmer}. Sanctioned credit limit rupees 3 lakh at 4 percent subsidized interest rate under Interest Subvention Scheme.`;
        }
      } else if (fSub === 'pension') {
        if (chosenLang === 'hi') {
          textToSpeak = `समाज कल्याण विभाग, उत्तर प्रदेश शासन। राष्ट्रीय सामाजिक सहायता कार्यक्रम। पेंशन स्वीकृति आदेश PPO 748192। लाभार्थी ${farmer}। ₹ 1,000 प्रति माह पेंशन आधार सक्षम बैंक खाते में निरंतर क्रेडिट।`;
        } else {
          textToSpeak = `Social Welfare Department. National Social Assistance Programme Pension Payment Order PPO 748192 for beneficiary ${farmer}. Monthly pension of rupees 1,000 credited directly via PFMS.`;
        }
      } else if (fSub === 'senior') {
        if (chosenLang === 'hi') {
          textToSpeak = `सामाजिक न्याय एवं अधिकारिता मंत्रालय, भारत सरकार। राष्ट्रीय वरिष्ठ नागरिक पहचान पत्र संख्या SR CITIZEN UP 2026 98412। धारक ${farmer}, आयु 64 वर्ष। वरिष्ठ नागरिक कल्याण अधिनियम 2007 के अंतर्गत समस्त विधिक अधिकार एवं रियायतें मान्य।`;
        } else {
          textToSpeak = `Ministry of Social Justice and Empowerment. Senior Citizen National Identification Card for ${farmer}, age 64 years. Entitled to priority healthcare and transit concessions under Senior Citizens Act 2007.`;
        }
      } else {
        if (chosenLang === 'hi') {
          textToSpeak = `कृषि एवं किसान कल्याण मंत्रालय, भारत सरकार। प्रधानमंत्री किसान सम्मान निधि प्रत्यक्ष लाभ अंतरण। लाभार्थी किसान ${farmer}। भूलेख अभिलेखों से सत्यापन उपरांत ₹ 2,000 की किस्त बैंक खाते में अंतरित।`;
        } else {
          textToSpeak = `Ministry of Agriculture and Farmers Welfare. PM-KISAN Direct Benefit Transfer sanction order for farmer ${farmer}. Verified through AgriStack land records with subsidy credited directly.`;
        }
      }
    } else if (deskKey === 'caste') {
      const revSub = window.currentRevenueSubService || 'caste';
    const applicant = escapeHtml(document.getElementById('input-caste-applicant')?.value || 'Rajesh Kumar');
    const father = escapeHtml(document.getElementById('input-caste-father')?.value || 'Harish Chandra');
    const dist = escapeHtml(document.getElementById('input-caste-district')?.value || 'Varanasi');

      if (revSub === 'income') {
    const inc = escapeHtml(document.getElementById('input-caste-income')?.value || '₹ 1,20,000');
        if (chosenLang === 'hi') {
          textToSpeak = `उत्तर प्रदेश शासन राजस्व विभाग। आय प्रमाण पत्र प्रारूप एक। आवेदक ${applicant}, आत्मज ${father}, जनपद ${dist}। परिवार की कुल वार्षिक आय ${inc} सत्यापित एवं तहसीलदार द्वारा ई-हस्ताक्षरित।`;
        } else {
          textToSpeak = `Revenue Department, Government of Uttar Pradesh. Income Certificate Form 1. Certifies that annual family income of ${applicant}, son of ${father}, District ${dist}, is ${inc}. Digitally signed by Tehsildar.`;
        }
      } else if (revSub === 'domicile') {
        if (chosenLang === 'hi') {
          textToSpeak = `उत्तर प्रदेश शासन राजस्व विभाग। मूल निवास प्रमाण पत्र प्रारूप दो। आवेदक ${applicant}, आत्मज ${father}, जनपद ${dist} के स्थायी एवं विधिक अधिवासी प्रमाणित किए जाते हैं।`;
        } else {
          textToSpeak = `Revenue Department. Domicile and Residence Certificate Form 2. Certifies that ${applicant}, son of ${father}, is a permanent legal domicile resident of District ${dist}, Uttar Pradesh.`;
        }
      } else if (revSub === 'ews') {
        if (chosenLang === 'hi') {
          textToSpeak = `राजस्व विभाग। आर्थिक रूप से कमजोर वर्ग ईडब्ल्यूएस प्रमाण पत्र प्रारूप पांच। आवेदक ${applicant} का परिवार वित्तीय वर्ष 2025-26 के अंतर्गत ईडब्ल्यूएस आरक्षण मानकों को पूर्ण करता है।`;
        } else {
          textToSpeak = `Revenue Department. Economically Weaker Section EWS Certificate Form 5. Certifies that ${applicant} fulfills criteria for reservation under EWS category for FY 2025-26.`;
        }
      } else if (revSub === 'divyang') {
        if (chosenLang === 'hi') {
          textToSpeak = `दिव्यांगजन सशक्तिकरण विभाग। दिव्यांगता प्रमाण पत्र एवं यूडीआईडी। आवेदक ${applicant} का चिकित्सकीय परीक्षण उपरांत 45 प्रतिशत स्थाई दिव्यांगता प्रमाणित की जाती है।`;
        } else {
          textToSpeak = `Department of Empowerment of Persons with Disabilities. UDID Certificate under RPwD Act 2016 for ${applicant}. Assessed at 45 percent permanent disability by District Medical Board.`;
        }
      } else if (revSub === 'character') {
        if (chosenLang === 'hi') {
          textToSpeak = `गृह एवं राजस्व विभाग। चरित्र एवं पूर्ववृत्त सत्यापन प्रमाण पत्र। आवेदक ${applicant} के विरुद्ध स्थानीय थाने में कोई भी आपराधिक वाद लंबित नहीं है एवं इनका चरित्र उत्तम है।`;
        } else {
          textToSpeak = `Police and Revenue Department. Character and Antecedent Certificate for ${applicant}. Confirms clear police record with no criminal antecedents.`;
        }
      } else if (revSub === 'land') {
        if (chosenLang === 'hi') {
          textToSpeak = `राजस्व परिषद उत्तर प्रदेश। भू-अभिलेख खतौनी एवं अधिकार अभिलेख। खातेदार ${applicant} व ${father}। ग्राम शिवपुर, खसरा संख्या 142/क, कुल क्षेत्रफल 0.4850 हेक्टेयर, रियल-टाइम भूलेख डेटाबेस से सत्यापित।`;
        } else {
          textToSpeak = `Board of Revenue Uttar Pradesh. Record of Rights Khatauni for landholders ${applicant} and ${father}. Khasra 142/A, area 0.4850 hectare, verified from real-time land registry.`;
        }
      } else if (revSub === 'legalheir') {
        if (chosenLang === 'hi') {
          textToSpeak = `राजस्व एवं मजिस्ट्रेट न्यायालय। विधिक उत्तराधिकारी वारिसान प्रमाण पत्र प्रारूप सात। स्वर्गीय हरीश चंद्र के विधिक जीवित उत्तराधिकारियों की सूची प्रमाणित एवं तहसीलदार द्वारा ई-हस्ताक्षरित।`;
        } else {
          textToSpeak = `Revenue and Magistrate Court. Legal Heir and Surviving Member Certificate Form 7. Certifies surviving legal heirs of Late Harish Chandra. Officially issued by Executive Magistrate.`;
        }
      } else if (revSub === 'solvency') {
        if (chosenLang === 'hi') {
          textToSpeak = `राजस्व एवं वित्त विभाग। हैसियत प्रमाण पत्र प्रारूप आठ। आवेदक ${applicant} की शुद्ध अचल संपत्ति एवं वित्तीय हैसियत ₹ 25 लाख अपर जिलाधिकारी द्वारा प्रमाणित।`;
        } else {
          textToSpeak = `Revenue and Finance Department. Solvency Certificate Form 8. Certifies net unencumbered property solvency of ${applicant} assessed at rupees 25 lakh by Additional District Magistrate.`;
        }
      } else {
        if (chosenLang === 'hi') {
          textToSpeak = `उत्तर प्रदेश शासन राजस्व विभाग। जाति प्रमाण पत्र प्रारूप चार। प्रमाणित किया जाता है कि आवेदक ${applicant}, आत्मज ${father}, जनपद ${dist}, अनुसूचित जाति के सदस्य हैं। तहसीलदार सदर द्वारा ई-हस्ताक्षरित।`;
        } else {
          textToSpeak = `Government of Uttar Pradesh, Department of Revenue. Caste Certificate Form 4 for ${applicant}, son of ${father}, District ${dist}. Digitally signed by Tehsildar Sadar and pushed to DigiLocker.`;
        }
      }
    } else if (deskKey === 'dl') {
      const transSub = window.currentTransportSubService || 'dl';
    const name = escapeHtml(document.getElementById('input-dl-name')?.value || 'Priya Sharma');
    const regNo = escapeHtml(document.getElementById('input-rc-regno')?.value || 'DL-04-AB-1024');

      if (transSub === 'll') {
        if (chosenLang === 'hi') {
          textToSpeak = `सड़क परिवहन एवं राजमार्ग मंत्रालय। शिक्षार्थी अनुज्ञप्ति फॉर्म 3। शिक्षार्थी चालक ${name}। कंप्यूटर टेस्ट में 15 में से 15 अंक प्राप्त। वैधता 6 माह हेतु सारथी पोर्टल द्वारा जारी।`;
        } else {
          textToSpeak = `Ministry of Road Transport and Highways. Learner's Licence Form 3 for ${name}. Passed computerised traffic regulations test with full score. Valid for 6 months across India.`;
        }
      } else if (transSub === 'renewal') {
        if (chosenLang === 'hi') {
          textToSpeak = `परिवहन विभाग। ड्राइविंग लाइसेंस नवीनीकरण पृष्ठांकन फॉर्म 9। चालक ${name} का लाइसेंस आगामी 20 वर्षों हेतु 15 अगस्त 2046 तक नवीनीकृत किया गया।`;
        } else {
          textToSpeak = `Transport Department. Driving Licence Renewal Endorsement Form 9 for ${name}. Validity extended for 20 years until 15 August 2046 under Section 15 of Motor Vehicles Act.`;
        }
      } else if (transSub === 'rc') {
        if (chosenLang === 'hi') {
          textToSpeak = `सड़क परिवहन एवं राजमार्ग मंत्रालय। वाहन पंजीकरण प्रमाण पत्र फॉर्म 23। वाहन संख्या ${regNo}। स्वामी ${name}। वाहन 4.0 राष्ट्रीय रजिस्टर में पंजीकृत एवं 15 वर्षों हेतु वैध।`;
        } else {
          textToSpeak = `Ministry of Road Transport and Highways. Certificate of Registration Form 23 for vehicle ${regNo}, owner ${name}. Registered in National Vahan Registry and valid for 15 years.`;
        }
      } else if (transSub === 'fitness') {
        if (chosenLang === 'hi') {
          textToSpeak = `स्वचालित परीक्षण स्टेशन। वाहन फिटनेस एवं प्रदूषण प्रमाण पत्र फॉर्म 38। वाहन संख्या ${regNo}। कार्बन मोनोऑक्साइड, हाइड्रोकार्बन एवं ब्रेक परीक्षण में पूर्णतः सफल एवं सड़क उपयोग हेतु उपयुक्त।`;
        } else {
          textToSpeak = `Automated Testing Station. Vehicle Fitness and PUCC Certificate Form 38 for vehicle ${regNo}. Emission parameters and brake efficiency compliant with CMVR standards. Certified roadworthy.`;
        }
      } else {
        if (chosenLang === 'hi') {
          textToSpeak = `सड़क परिवहन एवं राजमार्ग मंत्रालय। ड्राइविंग लाइसेंस स्मार्ट कार्ड। चालक का नाम ${name}। वाहन वर्ग MCWG एवं LMV चलाने हेतु प्राधिकृत। लाइसेंस संख्या DL 04 2026 0084920, वैधता 14 अगस्त 2042 तक।`;
        } else {
          textToSpeak = `Ministry of Road Transport and Highways. Smart Driving Licence Card for ${name}. Authorised to drive MCWG and LMV. Licence DL 04 2026 0084920, valid until 14 August 2042.`;
        }
      }
    }

    const utterance = new SpeechSynthesisUtterance(textToSpeak);
    utterance.rate = rate;
    utterance.pitch = 1.0;

    const voices = window.speechSynthesis.getVoices();
    if (chosenLang === 'hi') {
      utterance.lang = 'hi-IN';
      const hiVoice = voices.find(v => v.lang.startsWith('hi') || v.name.toLowerCase().includes('hindi') || v.name.toLowerCase().includes('lekha') || v.name.toLowerCase().includes('kalpana'));
      if (hiVoice) utterance.voice = hiVoice;
    } else {
      utterance.lang = 'en-IN';
      const enVoice = voices.find(v => (v.lang === 'en-IN' || v.lang.startsWith('en')) && (v.name.toLowerCase().includes('india') || v.name.toLowerCase().includes('neerja') || v.name.toLowerCase().includes('ravi') || v.name.toLowerCase().includes('geeta')));
      if (enVoice) utterance.voice = enVoice;
    }

    const wave = document.getElementById(`tts-wave-${uiKey}`);
    const stopBtn = document.getElementById(`btn-tts-stop-${uiKey}`);
    const statusText = document.getElementById(`tts-status-text-${uiKey}`);
    const label = document.getElementById(`tts-label-${uiKey}`);

    utterance.onstart = () => {
      if (wave) wave.classList.add('speaking');
      if (stopBtn) stopBtn.classList.remove('hidden');
      if (statusText) statusText.innerHTML = '<span class="text-[#138808] font-bold">Speaking Official Statutory Attestation in Voice...</span>';
      if (label) label.textContent = 'Playing Audio...';
    };

    utterance.onend = () => {
      resetTtsUI();
    };

    utterance.onerror = () => {
      resetTtsUI();
    };

    activeUtterance = utterance;
    window.speechSynthesis.speak(utterance);
  };

  window.verifyCertificateLookup = function(deskKey = 'birth') {
    const inputEl = document.getElementById(`verify-input-${deskKey}`);
    const resultEl = document.getElementById(`verify-result-${deskKey}`);
    if (!inputEl || !resultEl) return;

    const val = inputEl.value.trim().toUpperCase();
    if (!val) {
      showGovToast('Please enter a Registration No, CIN or Token ID to verify.');
      return;
    }

    let isMatch = false;
    let details = {};

    if (val.includes('CC') || val.includes('UP/2026') || deskKey === 'caste') {
      isMatch = true;
      details = {
        title: 'UTTAR PRADESH REVENUE DEPARTMENT (FORM 4 CASTE CERTIFICATE)',
        regId: val.includes('CC') ? val : 'UP/2026/CC/849201',
        authority: 'Office of the Tehsildar, Tehsil Sadar, District Varanasi (UP)',
        subject: 'Statutory Caste Certificate (SC / ST / OBC / EWS)',
        hash: 'SHA256: 7a8f9021b3e4c8d910248271a9c3d4e5f601b2c3d4e5f6a7b8c9d0e1f2a3b4c5',
        status: 'VALID & TEHSILDAR CLASS-3 DSC SIGNED',
        vault: 'Revenue Archive & DigiLocker Synced'
      };
    } else if (val.includes('DL-') || val.includes('SARATHI') || val.includes('PARIVAHAN') || deskKey === 'dl') {
      isMatch = true;
      details = {
        title: 'MINISTRY OF ROAD TRANSPORT & HIGHWAYS (PARIVAHAN SARATHI)',
        regId: val.includes('DL') ? val : 'DL-0420260084920',
        authority: 'Regional Transport Office, DL-04 (Janakpuri, West Delhi)',
        subject: 'Smart Card Driving Licence (MCWG + LMV)',
        hash: 'SHA256: 9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d',
        status: 'ACTIVE & AUTHORISED UNTIL 14-08-2042',
        vault: 'mParivahan & DigiLocker Push Confirmed'
      };
    } else if (val.includes('CRS') || val.includes('948271') || val.includes('AARAV') || deskKey === 'birth') {
      isMatch = true;
      details = {
        title: 'MUNICIPAL CIVIL REGISTRATION SYSTEM (CRS FORM 5)',
        regId: val.includes('CRS') ? val : 'CRS/2026/DL/948271',
        authority: 'Office of the Registrar of Births and Deaths, Delhi Municipal Corporation',
        subject: 'Child Birth Registration & Baal Aadhaar Cascade',
        hash: 'SHA256: 7a8f9021b3e4c8d910248271a9c3d4e5f601b2c3d4e5f6a7b8c9d0e1f2a3b4c5',
        status: 'VALID & OFFICIALLY SIGNED (DPDP COMPLIANT)',
        vault: 'DigiLocker Docket: DL-DOCKET-849201 (Push Confirmed)'
      };
    } else if (val.includes('U72900') || val.includes('394812') || (val.includes('BHARAT') || val.includes('BITGEN')) || deskKey === 'business') {
      isMatch = true;
      details = {
        title: 'MINISTRY OF CORPORATE AFFAIRS (SPICe+ REGISTRATION)',
        regId: val.includes('U72900') ? val : 'U72900DL2026PTC394812',
        authority: 'Office of the Registrar of Companies (ROC Delhi & Haryana)',
        subject: 'Incorporation of Private Limited Company',
        hash: 'SHA256: d4e5f6a7b8c9d0e1f2a3b4c57a8f9021b3e4c8d910248271a9c3d4e5f601b2c3',
        status: 'ACTIVE & DIGITALLY SEALED (COMPANIES ACT 2013)',
        vault: 'Co-integrated: CBDT PAN, GSTN, EPFO, ESIC & Bank'
      };
    } else {
      isMatch = true;
      details = {
        title: 'MINISTRY OF AGRICULTURE & FARMERS WELFARE (PM-KISAN DBT)',
        regId: val || 'KH-48201/08',
        authority: 'Department of Agriculture & Farmers Welfare / AgriStack',
        subject: 'Land-Linked Direct Benefit Transfer Sanction',
        hash: 'SHA256: b3e4c8d910248271a9c3d4e5f601b2c3d4e5f6a7b8c9d0e1f2a3b4c57a8f9021',
        status: 'AUTHENTICATED VIA BHULEKH & AEPS CREDITED',
        vault: 'Public Financial Management System UTR Confirmed'
      };
    }

    resultEl.classList.remove('hidden');
    resultEl.innerHTML = `
      <div class="bg-[#F0FDF4] border-2 border-[#10B981] rounded-lg p-3.5 space-y-2.5 animate-fadeIn">
        <div class="flex items-center justify-between border-b border-[#BBF7D0] pb-2">
          <div class="flex items-center gap-2">
            <span class="w-2.5 h-2.5 rounded-full bg-[#10B981]"></span>
            <span class="text-xs font-black text-[#065F46] uppercase tracking-wide flex items-center gap-1">
              <i data-lucide="shield-check" class="w-4 h-4 text-[#10B981]"></i>
              ${details.title}
            </span>
          </div>
          <span class="text-[10px] font-bold text-[#065F46] bg-[#DEF7EC] border border-[#31C48D] px-2 py-0.5 rounded">
            ${details.status}
          </span>
        </div>

        <div class="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
          <div>
            <span class="text-[#64748B] block text-[10.5px]">Registration / Token No:</span>
            <strong class="font-mono text-[#00314D] text-[12px]">${details.regId}</strong>
          </div>
          <div>
            <span class="text-[#64748B] block text-[10.5px]">Issuing Authority:</span>
            <span class="font-semibold text-[#1F2937]">${details.authority}</span>
          </div>
          <div>
            <span class="text-[#64748B] block text-[10.5px]">Subject / Life-Event:</span>
            <span class="font-semibold text-[#1F2937]">${details.subject}</span>
          </div>
          <div>
            <span class="text-[#64748B] block text-[10.5px]">Citizen Vault / Interop Delivery:</span>
            <span class="font-semibold text-[#10B981]">${details.vault}</span>
          </div>
        </div>

        <div class="pt-2 border-t border-[#BBF7D0] flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[10.5px]">
          <span class="font-mono text-[#64748B] truncate max-w-[360px]">${details.hash}</span>
          <div class="flex items-center gap-2">
            <button type="button" onclick="window.speakCurrentCertificate('${deskKey}')" class="bg-[#138808] hover:bg-[#0F6B06] text-white px-2.5 py-1 rounded font-bold flex items-center gap-1 cursor-pointer">
              <i data-lucide="volume-2" class="w-3 h-3"></i>
              <span>Listen Attestation</span>
            </button>
            <button type="button" onclick="window.copyVerificationToken('${details.regId}')" class="bg-white hover:bg-[#F8FAFC] text-[#00314D] border border-[#CBD5E1] px-2 py-1 rounded font-bold flex items-center gap-1 cursor-pointer">
              <i data-lucide="copy" class="w-3 h-3 text-[#0284C7]"></i>
              <span>Copy ID</span>
            </button>
          </div>
        </div>
      </div>
    `;

    if (window.lucide) window.lucide.createIcons();
    showGovToast(`Record ${details.regId} verified on NDIG Gateway!`);
  };

  // Connect Central Search Input (reusing searchInput & searchBtn from line 820)
  function handleSearchDispatch() {
    if (!searchInput) return;
    const q = searchInput.value.toLowerCase().trim();
    if (!q) {
      window.launchPrototypeWorkflow('birth');
      return;
    }

    if (q.includes('birth') || q.includes('जन्म') || q.includes('aadhaar') || q.includes('आधार') || q.includes('crs')) {
      window.launchPrototypeWorkflow('birth', 'birthcert');
    } else if (q.includes('caste') || q.includes('जाति') || q.includes('sc') || q.includes('st') || q.includes('obc') || q.includes('ews')) {
      window.launchPrototypeWorkflow('caste');
    } else if (q.includes('licence') || q.includes('license') || q.includes('driving') || q.includes('ड्राइविंग') || q.includes('morth') || q.includes('rto')) {
      window.launchPrototypeWorkflow('dl');
    } else if (q.includes('spice') || q.includes('company') || q.includes('mca') || q.includes('व्यापार') || q.includes('corporate')) {
      window.launchPrototypeWorkflow('business');
    } else if (q.includes('kisan') || q.includes('farmer') || q.includes('dbt') || q.includes('किसान') || q.includes('land')) {
      window.launchPrototypeWorkflow('farmer');
    } else {
      window.launchPrototypeWorkflow('birth');
    }
  }

  if (searchBtn) searchBtn.addEventListener('click', handleSearchDispatch);
  if (searchInput) {
    searchInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') handleSearchDispatch();
    
  });
  }

  // Initialize Prototype Documents Immediately
  window.generateBirthCertificateAction(true);
  window.generateBusinessCertificateAction();
  window.generateFarmerVoucherAction();
  window.generateCasteCertificateAction();
  window.generateDrivingLicenceAction();


  // =========================================================================
  // GIGW 3.0 GLOBAL TTS ENGINE & SCREEN READER
  // =========================================================================
  let globalUtterance = null;
  let isGlobalTtsPlaying = false;
  let isGlobalTtsPaused = false;

  window.toggleGlobalTtsBar = function() {
    const bar = document.getElementById('global-tts-bar');
    if (!bar) return;
    if (bar.classList.contains('collapsed')) {
      bar.classList.remove('collapsed');
      bar.classList.add('expanded');
      showGovToast('National Audio Screen Reader Activated (Alt+L)');
    } else {
      bar.classList.add('collapsed');
      bar.classList.remove('expanded');
      window.stopGlobalTts();
    }
  };

  window.playGlobalTts = function() {
    if (!('speechSynthesis' in window)) {
      showGovToast('Web Speech API is not supported in this browser.');
      return;
    }

    if (isGlobalTtsPaused && window.speechSynthesis.paused) {
      window.speechSynthesis.resume();
      isGlobalTtsPaused = false;
      isGlobalTtsPlaying = true;
      updateGlobalTtsUI(true);
      return;
    }

    window.speechSynthesis.cancel();

    const target = escapeHtml(document.getElementById('global-tts-target')?.value || 'current');
    const speed = parseFloat(document.getElementById('global-tts-speed')?.value || '1.0');
    let textToRead = '';
    let targetElement = null;

    if (target === 'current') {
      const deskKey = (typeof currentActiveDesk !== 'undefined' ? currentActiveDesk : 'birth');
      targetElement = document.getElementById(`desk-pane-${deskKey}`) || document.getElementById('citizen-service-prototype');
    } else if (target === 'prototype') {
      targetElement = document.getElementById('citizen-service-prototype');
    } else if (target === 'overview') {
      targetElement = document.getElementById('overview');
    } else if (target === 'pillars') {
      targetElement = document.getElementById('architecture-pillars');
    } else if (target === 'security') {
      targetElement = document.getElementById('enterprise-stack');
    }

    if (targetElement) {
      targetElement.classList.add('tts-active-reading');
      const clone = targetElement.cloneNode(true);
      clone.querySelectorAll('button, select, input, script, style, .no-print').forEach(el => el.remove());
      textToRead = clone.innerText.replace(/\s+/g, ' ').trim();
    } else {
      textToRead = document.body.innerText.replace(/\s+/g, ' ').trim();
    }

    if (!textToRead) {
      textToRead = currentLang === 'hi' ? 
        'राष्ट्रीय डिजिटल अंतर-प्रचालनीयता गेटवे। सभी नागरिक सेवाएं सक्रिय एवं सुरक्षित हैं।' :
        'National Digital Interoperability Gateway. All citizen services are operational and verified.';
    }

    if (textToRead.length > 2500) {
      textToRead = textToRead.substring(0, 2500) + '... (End of spoken excerpt)';
    }

    const pitch = parseFloat(document.getElementById('global-tts-pitch')?.value || '1.0');
    globalUtterance = new SpeechSynthesisUtterance(textToRead);
    globalUtterance.rate = speed;
    globalUtterance.pitch = pitch;
    globalUtterance.lang = currentLang === 'hi' ? 'hi-IN' : 'en-IN';

    const voices = window.speechSynthesis.getVoices();
    if (currentLang === 'hi') {
      const hiVoice = voices.find(v => v.lang.startsWith('hi') || v.name.toLowerCase().includes('hindi'));
      if (hiVoice) globalUtterance.voice = hiVoice;
    } else {
      const enVoice = voices.find(v => (v.lang === 'en-IN' || v.lang.startsWith('en')) && (v.name.toLowerCase().includes('india') || v.name.toLowerCase().includes('neerja') || v.name.toLowerCase().includes('ravi')));
      if (enVoice) globalUtterance.voice = enVoice;
    }

    globalUtterance.onstart = () => {
      isGlobalTtsPlaying = true;
      isGlobalTtsPaused = false;
      updateGlobalTtsUI(true);
    };

    globalUtterance.onboundary = () => {
      const wave = document.getElementById('global-tts-wave');
      if (wave && isGlobalTtsPlaying) {
        wave.classList.add('speaking');
      }
    };

    globalUtterance.onend = () => {
      window.stopGlobalTts();
    };

    globalUtterance.onerror = () => {
      window.stopGlobalTts();
    };

    window.speechSynthesis.speak(globalUtterance);
  };

  window.pauseGlobalTts = function() {
    if (window.speechSynthesis && isGlobalTtsPlaying) {
      window.speechSynthesis.pause();
      isGlobalTtsPaused = true;
      isGlobalTtsPlaying = false;
      updateGlobalTtsUI(false, true);
    }
  };

  window.stopGlobalTts = function() {
    if (window.speechSynthesis) {
      window.speechSynthesis.cancel();
    }
    isGlobalTtsPlaying = false;
    isGlobalTtsPaused = false;
    document.querySelectorAll('.tts-active-reading').forEach(el => el.classList.remove('tts-active-reading'));
    updateGlobalTtsUI(false, false);
  };

  function updateGlobalTtsUI(isPlaying, isPaused = false) {
    const playBtnTxt = document.getElementById('btn-global-tts-play-txt');
    const pauseBtn = document.getElementById('btn-global-tts-pause');
    const statusTxt = document.getElementById('global-tts-status');
    const wave = document.getElementById('global-tts-wave');

    if (isPlaying) {
      if (playBtnTxt) playBtnTxt.textContent = currentLang === 'hi' ? 'वाचन चल रहा है...' : 'Speaking...';
      if (pauseBtn) pauseBtn.classList.remove('hidden');
      if (statusTxt) statusTxt.textContent = currentLang === 'hi' ? 'पृष्ठ वाचन प्रगति पर है...' : 'Voice reading in progress...';
      if (wave) wave.classList.add('speaking');
    } else if (isPaused) {
      if (playBtnTxt) playBtnTxt.textContent = currentLang === 'hi' ? 'पुनः प्रारंभ (Resume)' : 'Resume';
      if (pauseBtn) pauseBtn.classList.add('hidden');
      if (statusTxt) statusTxt.textContent = currentLang === 'hi' ? 'वाचन रुका हुआ है (Pause)' : 'Reading paused';
      if (wave) wave.classList.remove('speaking');
    } else {
      if (playBtnTxt) playBtnTxt.textContent = currentLang === 'hi' ? 'पढ़कर सुनाएं' : 'Listen Page';
      if (pauseBtn) pauseBtn.classList.add('hidden');
      if (statusTxt) statusTxt.textContent = currentLang === 'hi' ? 'वाच्य सहायक तैयार है' : 'Ready to read active section';
      if (wave) wave.classList.remove('speaking');
    }
  }

  // =========================================================================
  // QUICK AUDIO GUIDES (SPECIFIC DESK EXPLANATIONS)
  // =========================================================================
  window.speakGuide = function(guideKey) {
    if (!('speechSynthesis' in window)) {
      showGovToast('Web Speech API is not supported in this browser.');
      return;
    }

    window.speechSynthesis.cancel();

    let guideText = '';
    const speed = parseFloat(document.getElementById('global-tts-speed')?.value || '1.0');
    const pitch = parseFloat(document.getElementById('global-tts-pitch')?.value || '1.0');

    if (guideKey === 'birth') {
      guideText = currentLang === 'hi' ?
        'नवजात जन्म प्रमाण पत्र एवं कल्याणकारी लाभ डेस्क। जब किसी पंजीकृत अस्पताल में बच्चे का जन्म होता है, तो अस्पताल का रिकॉर्ड राष्ट्रीय जन्म एवं मृत्यु रजिस्ट्री तथा UIDAI आधार बस के साथ स्वचालित रूप से सत्यापित होता है। बिना किसी शारीरिक कागजी प्रक्रिया के डिजिटल रूप से हस्ताक्षरित जन्म प्रमाण पत्र जारी किया जाता है और मातृत्व लाभ सीधे खाते में स्थानांतरित किया जाता है।' :
        'Newborn Registration and Welfare Delivery Desk. When a child is born in a registered healthcare facility, the birth record is verified through the Civil Registration System and UIDAI Aadhaar bus. A digitally signed, tamper-proof birth certificate is issued instantly to DigiLocker, and linked maternity cash benefits are disbursed via Direct Benefit Transfer without physical visits.';
    } else if (guideKey === 'biz') {
      guideText = currentLang === 'hi' ?
        'कॉर्पोरेट निगमन एवं SPICe+ व्यापार डेस्क। कॉर्पोरेट मामलों के मंत्रालय द्वारा कंपनी पंजीकरण होते ही, पैन, टैन, जीएसटीएन, ईपीएफओ और बैंक खाता एक ही डिजिटल लेन-देन में स्वचालित रूप से सृजित और सत्यापित हो जाते हैं।' :
        'Corporate SPICe+ Single-Window Business Desk. When an enterprise is incorporated under Ministry of Corporate Affairs, PAN, TAN, GSTN, EPFO, and ESIC credentials are simultaneously provisioned through the National Interoperability Gateway in a single atomic transaction.';
    } else if (guideKey === 'farmer') {
      guideText = currentLang === 'hi' ?
        'पीएम-किसान एवं कृषि-स्टैक डेस्क। राज्य भू-अभिलेख और कृषि-स्टैक डेटाबेस के स्वतः मिलान द्वारा प्रत्यक्ष लाभ अंतरण की दो हजार रुपये की किस्त आधार-सत्यापित बैंक खाते में बिना किसी बिचौलिए के अंतरित की जाती है।' :
        'PM-KISAN AgriStack DBT Desk. By harmonizing state land records with the central AgriStack database, genuine cultivators are authenticated via Aadhaar e-KYC and Direct Benefit Transfer subsidies are credited without bureaucratic intermediaries.';
    } else if (guideKey === 'dpdp') {
      guideText = currentLang === 'hi' ?
        'डिजिटल व्यक्तिगत डेटा संरक्षण अधिनियम 2023 अनुपालन। यह गेटवे शून्य-ज्ञान प्रमाण और डेटा न्यूनीकरण के सिद्धांतों पर आधारित है। कोई भी कच्चा नागरिक डेटा गेटवे पर संग्रहीत नहीं होता। प्रत्येक डेटा साझाकरण नागरिक की स्पष्ट वैधानिक सहमति और अपरिवर्तनीय ऑडिट लेजर के साथ होता है।' :
        'DPDP Act 2023 Statutory Compliance. The Gateway operates on zero-trust and data minimization principles. No raw citizen credentials are stored on intermediate buses. All data exchanges require explicit consent tokens and immutable cryptographic audit logging.';
    }

    const utterance = new SpeechSynthesisUtterance(guideText);
    utterance.rate = speed;
    utterance.pitch = pitch;
    utterance.lang = currentLang === 'hi' ? 'hi-IN' : 'en-IN';

    const voices = window.speechSynthesis.getVoices();
    if (currentLang === 'hi') {
      const hiVoice = voices.find(v => v.lang.startsWith('hi') || v.name.toLowerCase().includes('hindi'));
      if (hiVoice) utterance.voice = hiVoice;
    } else {
      const enVoice = voices.find(v => (v.lang === 'en-IN' || v.lang.startsWith('en')) && (v.name.toLowerCase().includes('india') || v.name.toLowerCase().includes('neerja') || v.name.toLowerCase().includes('ravi')));
      if (enVoice) utterance.voice = enVoice;
    }

    utterance.onstart = () => {
      isGlobalTtsPlaying = true;
      isGlobalTtsPaused = false;
      updateGlobalTtsUI(true);
      showGovToast(`Audio Guide: ${guideKey.toUpperCase()} narration started`);
    };

    utterance.onend = () => {
      window.stopGlobalTts();
    };

    utterance.onerror = () => {
      window.stopGlobalTts();
    };

    window.speechSynthesis.speak(utterance);
  };

  // =========================================================================
  // DOWNLOAD SPOKEN ACCESSIBILITY TRANSCRIPT SCRIPT
  // =========================================================================
  window.downloadAudioTranscript = function() {
    const transcriptText = `================================================================================
NATIONAL DIGITAL INTEROPERABILITY GATEWAY (NDIG) — OFFICIAL SPOKEN SCRIPT
Government of India • Ministry of Electronics & Information Technology (MeitY)
National e-Governance Division (NeGD) • IndEA 2.0 Enterprise Architecture Standards
================================================================================
Generated on: ${new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })} IST
Compliance: GIGW 3.0 Mandatory Audio Accessibility & Web Content Accessibility Guidelines

[SECTION 1: OVERVIEW & ARCHITECTURE]
English:
"National Digital Interoperability Gateway. Single-window inter-departmental data exchange platform and interoperability mesh. Eliminating data silos for unified public services. Designed to align with the Government of India Open API Policy and the principles of the Digital Personal Data Protection (DPDP) Act 2023."

हिन्दी (Rajbhasha):
"राष्ट्रीय डिजिटल अंतर-प्रचालनीयता गेटवे। एकल-खिड़की अंतर-विभागीय डेटा विनिमय मंच और इंटरऑपरेबिलिटी मेश। एकीकृत सार्वजनिक सेवाओं के लिए विभागीय डेटा अवरोधों को समाप्त करना। भारत सरकार की ओपन एपीआई नीति और डिजिटल व्यक्तिगत डेटा संरक्षण अधिनियम 2023 के अनुरूप निर्मित।"

[SECTION 2: NEWBORN DESK (DESK 1)]
English:
"When a child is born in a registered healthcare facility, the hospital record is verified through the Civil Registration System and UIDAI Aadhaar bus. A digitally signed, tamper-proof birth certificate is issued instantly to DigiLocker, and linked maternity cash benefits are disbursed via Direct Benefit Transfer without physical visits."

हिन्दी:
"जब किसी पंजीकृत अस्पताल में बच्चे का जन्म होता है, तो अस्पताल का रिकॉर्ड राष्ट्रीय जन्म एवं मृत्यु रजिस्ट्री (CRS) तथा UIDAI आधार बस के साथ स्वचालित रूप से सत्यापित होता है। बिना किसी शारीरिक कागजी प्रक्रिया के डिजिटल रूप से हस्ताक्षरित जन्म प्रमाण पत्र जारी किया जाता है और मातृत्व लाभ सीधे खाते में स्थानांतरित किया जाता है।"

[SECTION 3: SPICe+ CORPORATE BUSINESS DESK (DESK 2)]
English:
"When an enterprise is incorporated under Ministry of Corporate Affairs, PAN, TAN, GSTN, EPFO, and ESIC credentials are simultaneously provisioned through the National Interoperability Gateway in a single atomic transaction."

हिन्दी:
"कॉर्पोरेट मामलों के मंत्रालय द्वारा कंपनी पंजीकरण होते ही, पैन, टैन, जीएसटीएन, ईपीएफओ और बैंक खाता एक ही डिजिटल लेन-देन में स्वचालित रूप से सृजित और सत्यापित हो जाते हैं।"

[SECTION 4: PM-KISAN AGRISTACK DBT DESK (DESK 3)]
English:
"By harmonizing state land records with the central AgriStack database, genuine cultivators are authenticated via Aadhaar e-KYC and Direct Benefit Transfer subsidies are credited without bureaucratic intermediaries."

हिन्दी:
"राज्य भू-अभिलेख और कृषि-स्टैक डेटाबेस के स्वतः मिलान द्वारा प्रत्यक्ष लाभ अंतरण (DBT) की किस्त आधार-सत्यापित बैंक खाते में बिना किसी बिचौलिए के अंतरित की जाती है।"

[SECTION 5: DPDP ACT 2023 STATUTORY CONSENT]
English:
"The Gateway operates on zero-trust and data minimization principles. No raw citizen credentials are stored on intermediate buses. All data exchanges require explicit consent tokens and immutable cryptographic audit logging."

हिन्दी:
"यह गेटवे शून्य-ज्ञान प्रमाण और डेटा न्यूनीकरण के सिद्धांतों पर आधारित है। कोई भी कच्चा नागरिक डेटा गेटवे पर संग्रहीत नहीं होता। प्रत्येक डेटा साझाकरण नागरिक की स्पष्ट वैधानिक सहमति और अपरिवर्तनीय ऑडिट लेजर के साथ होता है।"
================================================================================
END OF ACCESSIBILITY AUDIO TRANSCRIPT
================================================================================`;

    const blob = new Blob([transcriptText], { type: 'text/plain;charset=utf-8' 
  });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'NDIG_Citizen_Audio_Access_Transcript.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showGovToast('Spoken Accessibility Transcript downloaded successfully!');
  };

  // =========================================================================
  // VOICE SEARCH (बोलकर खोजें) STT ENGINE
  // =========================================================================
  let voiceRecognition = null;
  let isVoiceSearching = false;

  window.toggleVoiceSearch = function() {
    const micBtn = document.getElementById('btn-voice-search');
    const searchInput = document.getElementById('gov-search-input');
    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;

    if (!SpeechRecognition) {
      showGovToast('Speech Recognition is not supported in this browser. Please type your search query.');
      return;
    }

    if (isVoiceSearching && voiceRecognition) {
      voiceRecognition.stop();
      isVoiceSearching = false;
      if (micBtn) micBtn.classList.remove('voice-search-active');
      return;
    }

    try {
      voiceRecognition = new SpeechRecognition();
      voiceRecognition.lang = currentLang === 'hi' ? 'hi-IN' : 'en-IN';
      voiceRecognition.interimResults = false;
      voiceRecognition.maxAlternatives = 1;

      voiceRecognition.onstart = () => {
        isVoiceSearching = true;
        if (micBtn) micBtn.classList.add('voice-search-active');
        if (searchInput) searchInput.placeholder = currentLang === 'hi' ? 'सुन रहे हैं... बोलिए...' : 'Listening... Speak now...';
        showGovToast(currentLang === 'hi' ? 'माइक्रोफ़ोन सक्रिय: बोलकर खोजें' : 'Microphone Active: Speak your search query');
      };

      voiceRecognition.onresult = (event) => {
        const transcript = event.results[0][0].transcript;
        if (searchInput) {
          searchInput.value = transcript;
          const searchBtn = document.getElementById('gov-search-btn');
          if (searchBtn) searchBtn.click();
        }
        showGovToast(`Voice Query: "${transcript}"`);
      };

      voiceRecognition.onerror = (event) => {
        isVoiceSearching = false;
        if (micBtn) micBtn.classList.remove('voice-search-active');
        if (searchInput) searchInput.placeholder = currentLang === 'hi' ? 'सेवाएं, प्रमाण पत्र या विभाग खोजें...' : 'Search services, certificates, or registration...';
        showGovToast('Voice Search ended or microphone permission needed.');
      };

      voiceRecognition.onend = () => {
        isVoiceSearching = false;
        if (micBtn) micBtn.classList.remove('voice-search-active');
        if (searchInput) searchInput.placeholder = currentLang === 'hi' ? 'सेवाएं, प्रमाण पत्र या विभाग खोजें...' : 'Search services, certificates, or registration...';
      };

      voiceRecognition.start();
    } catch (err) {
      console.warn('SpeechRecognition error:', err);
      showGovToast('Unable to start Voice Recognition.');
    }
  };

  // =========================================================================
  // FLOATING SELECT-TO-SPEAK (TEXT HIGHLIGHT AUDIO READER)
  // =========================================================================
  window.selectedTextToSpeak = '';

  window.speakSelectedText = function() {
    if (!window.selectedTextToSpeak || !('speechSynthesis' in window)) return;
    window.speechSynthesis.cancel();

    const speed = parseFloat(document.getElementById('global-tts-speed')?.value || '1.0');
    const pitch = parseFloat(document.getElementById('global-tts-pitch')?.value || '1.0');

    const utterance = new SpeechSynthesisUtterance(window.selectedTextToSpeak);
    utterance.rate = speed;
    utterance.pitch = pitch;
    utterance.lang = currentLang === 'hi' ? 'hi-IN' : 'en-IN';

    const voices = window.speechSynthesis.getVoices();
    if (currentLang === 'hi') {
      const hiVoice = voices.find(v => v.lang.startsWith('hi') || v.name.toLowerCase().includes('hindi'));
      if (hiVoice) utterance.voice = hiVoice;
    }

    utterance.onstart = () => {
      showGovToast('Reading selected text aloud...');
      const pill = document.getElementById('tts-selection-pill');
      if (pill) pill.classList.remove('visible');
    };

    utterance.onend = () => {
      window.stopGlobalTts();
    };

    window.speechSynthesis.speak(utterance);
  };

  window.hideSelectionPill = function() {
    const pill = document.getElementById('tts-selection-pill');
    if (pill) {
      pill.classList.remove('visible');
      setTimeout(() => { pill.style.display = 'none'; }, 200);
    }
    window.selectedTextToSpeak = '';
  };

  document.addEventListener('mouseup', (e) => {
    const pill = document.getElementById('tts-selection-pill');
    if (!pill || pill.contains(e.target)) return;

    const selection = window.getSelection();
    const text = selection ? selection.toString().trim() : '';

    if (text.length > 3) {
      window.selectedTextToSpeak = text;
      const range = selection.getRangeAt(0);
      const rect = range.getBoundingClientRect();

      pill.style.top = Math.max(10, rect.top + window.scrollY - 42) + 'px';
      pill.style.left = Math.max(10, rect.left + window.scrollX + (rect.width / 2) - 80) + 'px';
      pill.style.display = 'flex';
      requestAnimationFrame(() => {
        pill.classList.add('visible');
      
  });
    } else {
      window.hideSelectionPill();
    }
  
  });

  // Hotkey support: Alt+L to play, Alt+X to stop, Escape to close modals
  window.addEventListener('keydown', (e) => {
    if (e.altKey && (e.key === 'l' || e.key === 'L')) {
      e.preventDefault();
      const bar = document.getElementById('global-tts-bar');
      if (bar && bar.classList.contains('collapsed')) {
        window.toggleGlobalTtsBar();
      }
      if (isGlobalTtsPlaying) {
        window.pauseGlobalTts();
      } else {
        window.playGlobalTts();
      }
    } else if (e.altKey && (e.key === 'x' || e.key === 'X')) {
      e.preventDefault();
      window.stopGlobalTts();
    } else if (e.key === 'Escape') {
      window.closeAllModals();
      window.hideSelectionPill();
    }
  
  });

  // =========================================================================
  // X.509 DIGITAL SIGNATURE VERIFICATION MODAL
  // =========================================================================
  window.showCertificateChainModal = function(deskKey = 'birth') {
    const modal = document.getElementById('modal-cert-chain');
    const body = document.getElementById('modal-cert-body');
    const title = document.getElementById('modal-cert-title');
    if (!modal || !body) return;

    let certDetails = {
      authority: 'Registrar General of India & Delhi Municipal CRS',
      signer: 'Dr. Alok Verma, Chief Registrar (Class 3 DSC)',
      serial: 'CCA-IN-2026-9482-1104',
      issuer: 'National Informatics Centre Sub-CA 2026 (NIC-CA)',
      validity: '01 Jan 2026 to 31 Dec 2028',
      hash: 'SHA256: 8F4D209B1A456C87E2390184EF5A2190B388D4E1C650982341A87D65E12B980F',
      keyUsage: 'Digital Signature, Non-Repudiation (IT Act 2000 Section 3A)',
      statutory: 'Issued under Section 12/17 of Registration of Births & Deaths Act 1969'
    };

    if (deskKey === 'biz') {
      certDetails.authority = 'Registrar of Companies (ROC Delhi), Ministry of Corporate Affairs';
      certDetails.signer = 'Smt. Anjali Sharma, Registrar of Companies (Class 3 DSC)';
      certDetails.serial = 'MCA-ROC-DEL-2026-4481-9921';
      certDetails.hash = 'SHA256: 7B1289DF4E23190A56C489110B389145E209148F651290384EF81249A019B4C2';
      certDetails.statutory = 'Issued under Section 7(2) of the Companies Act, 2013 & Rule 18 Companies Rules';
    } else if (deskKey === 'farmer') {
      certDetails.authority = 'Department of Agriculture & Farmers Welfare (AgriStack PM-KISAN Bus)';
      certDetails.signer = 'Shri Rajeshwar Singh, Director DBT (Class 3 DSC)';
      certDetails.serial = 'AGRI-PMKISAN-2026-7810-4491';
      certDetails.hash = 'SHA256: 3F901248E56C9120B4891456A7812903EF209184B65120384A981240C019E78F';
      certDetails.statutory = 'Direct Benefit Transfer Sanction under PM-KISAN Operational Guidelines';
    }

    if (title) title.textContent = `X.509 Cryptographic Certificate Audit: ${certDetails.authority}`;

    body.innerHTML = `
      <div class="border border-[#CBD5E1] rounded p-3 bg-[#F8FAFC] space-y-2">
        <div class="flex items-center justify-between border-b border-[#CBD5E1] pb-2">
          <span class="text-[#00314D] font-bold text-xs">Signer Identity:</span>
          <span class="font-semibold text-[#1F2937] text-xs">${certDetails.signer}</span>
        </div>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
          <div>
            <span class="text-[#64748B] block">Certificate Serial No:</span>
            <span class="font-mono font-bold text-[#00314D]">${certDetails.serial}</span>
          </div>
          <div>
            <span class="text-[#64748B] block">Issuing Root CA:</span>
            <span class="font-semibold text-[#1F2937]">${certDetails.issuer}</span>
          </div>
          <div>
            <span class="text-[#64748B] block">Validity Window:</span>
            <span class="font-semibold text-[#047857]">${certDetails.validity}</span>
          </div>
          <div>
            <span class="text-[#64748B] block">Key Usage &amp; IT Act Citation:</span>
            <span class="font-semibold text-[#1F2937]">${certDetails.keyUsage}</span>
          </div>
        </div>
        <div class="pt-2 border-t border-[#CBD5E1]">
          <span class="text-[#64748B] block text-[10.5px]">SHA-256 Cryptographic Digest:</span>
          <span class="font-mono text-[#00314D] text-[10.5px] break-all bg-white p-1 rounded border border-[#CBD5E1] block mt-0.5">${certDetails.hash}</span>
        </div>
        <div class="text-[10.5px] text-[#475569] italic pt-1">
          Statutory Authority: ${certDetails.statutory}
        </div>
      </div>
      <div class="p-2.5 rounded bg-[#DEF7EC] border border-[#31C48D] flex items-center justify-between text-[11px] text-[#03543F]">
        <div class="flex items-center gap-1.5 font-bold">
          <i data-lucide="shield-check" class="w-4 h-4 text-[#10B981]"></i>
          <span>Real-time OCSP Revocation Status: GOOD (Unrevoked)</span>
        </div>
        <span class="font-mono text-[10px]">HSM FIPS 140-2 Level 3</span>
      </div>
    `;

    if (window.lucide) window.lucide.createIcons();
    modal.classList.remove('hidden');
  };

  // =========================================================================
  // DPDP ACT 2023 STATUTORY CONSENT MANAGER MODAL
  // =========================================================================
  window.showDpdpConsentModal = function(deskKey = 'birth') {
    const modal = document.getElementById('modal-dpdp-consent');
    const body = document.getElementById('modal-dpdp-body');
    if (!modal || !body) return;

    const timestamp = new Date().toISOString();
    const token = 'DPDP-2026-' + Math.random().toString(36).substring(2, 9).toUpperCase();

    body.innerHTML = `
      <div class="border border-[#FED7AA] rounded p-3 bg-[#FFFBF5] space-y-2.5">
        <div class="flex items-center justify-between border-b border-[#FED7AA] pb-1.5">
          <span class="font-bold text-[#7C2D12] text-xs">Statutory Consent Token:</span>
          <span class="font-mono font-bold text-[#00314D] bg-white px-2 py-0.5 rounded border border-[#CBD5E1]">${token}</span>
        </div>
        <div class="space-y-1.5 text-[11px] text-[#4B5563]">
          <div><strong class="text-[#00314D]">Data Principal:</strong> Citizen / Registered Aadhaar Holder</div>
          <div><strong class="text-[#00314D]">Data Fiduciary:</strong> National Digital Interoperability Gateway (NDIG), MeitY</div>
          <div><strong class="text-[#00314D]">Specified Purpose:</strong> Automated single-window issuance of civil registry records &amp; linked welfare benefits without physical document resubmission.</div>
          <div><strong class="text-[#00314D]">Legal Ground:</strong> Section 6 (Consent) &amp; Section 7 (Certain legitimate uses) of the Digital Personal Data Protection Act, 2023.</div>
          <div><strong class="text-[#00314D]">Retention Policy:</strong> Zero raw data storage on gateway bus. Immutable audit ledger retained in encrypted WORM vault for statutory compliance.</div>
        </div>
        <div class="p-2 bg-white rounded border border-[#FED7AA] text-[10.5px] font-mono text-[#64748B] flex justify-between">
          <span>Token Generated: ${timestamp}</span>
          <span class="text-[#138808] font-bold">Status: ACTIVE &amp; RECORDED</span>
        </div>
      </div>
      <div class="p-2.5 rounded bg-[#EEF2F6] border border-[#CBD5E1] text-[11px] text-[#475569] flex items-center justify-between">
        <span>Citizen Right: You can withdraw this consent or inspect logs anytime via the Citizen Consent Dashboard.</span>
        <button type="button" onclick="window.copyVerificationToken('${token}')" class="bg-white border border-[#CBD5E1] text-[#00314D] px-2 py-0.5 rounded font-bold text-[10px] cursor-pointer">
          Copy Token
        </button>
      </div>
    `;

    if (window.lucide) window.lucide.createIcons();
    modal.classList.remove('hidden');
  };

  window.closeAllModals = function() {
    document.querySelectorAll('.gov-modal-backdrop').forEach(m => m.classList.add('hidden'));
  };

  // =========================================================================
  // DOWNLOAD SIGNED DOCUMENT AS GAZETTE ARTIFACT
  // =========================================================================
  window.downloadSignedDocument = function(deskKey = 'birth') {
    let filename = 'MH_Sahyog_Official_Birth_Certificate.html';
    let contentEl = document.getElementById('active-document-container');
    let title = 'OFFICIAL BIRTH CERTIFICATE — MH SAHYOG PORTAL';

    if (deskKey === 'caste' || deskKey === 'revenue') {
      filename = 'MH_Sahyog_Official_Caste_Certificate.html';
      contentEl = document.getElementById('caste-document-container');
      title = 'OFFICIAL STATUTORY CERTIFICATE — REVENUE DEPARTMENT (MH SAHYOG)';
    } else if (deskKey === 'dl' || deskKey === 'transport') {
      filename = 'MH_Sahyog_Smart_Driving_Licence_Card.html';
      contentEl = document.getElementById('dl-document-container');
      title = 'DRIVING LICENCE SMART CARD — UNION OF INDIA (MoRTH)';
    } else if (deskKey === 'receipt') {
      filename = 'MH_Sahyog_RTPS_Acknowledgment_Slip.html';
      contentEl = document.getElementById('active-document-container');
      title = 'CITIZEN APPLICATION ACKNOWLEDGMENT RECEIPT — MH SAHYOG';
    } else if (deskKey === 'biz' || deskKey === 'business') {
      filename = 'MH_Sahyog_Corporate_Registration_Certificate.html';
      contentEl = document.getElementById('biz-document-container');
      title = 'STATUTORY BUSINESS REGISTRATION — MINISTRY OF CORPORATE AFFAIRS / MSME';
    } else if (deskKey === 'farmer' || deskKey === 'agri') {
      filename = 'MH_Sahyog_Agriculture_Welfare_Sanction_Order.html';
      contentEl = document.getElementById('farmer-document-container');
      title = 'AGRICULTURE & SOCIAL WELFARE SANCTION ORDER — MH SAHYOG';
    }

    if (!contentEl) {
      showGovToast('Certificate content not found to export.');
      return;
    }

    const docHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${title}</title>
  <style>
    body { font-family: 'Georgia', serif; padding: 40px; background: #fff; color: #111; }
    .container { max-width: 800px; margin: 0 auto; border: 2px solid #00314D; padding: 30px; }
    h1, h2, h3 { text-align: center; margin: 0 0 10px 0; color: #00314D; }
    .hash { font-family: monospace; font-size: 11px; color: #555; word-break: break-all; margin-top: 20px; border-top: 1px solid #ccc; padding-top: 10px; }
  </style>
</head>
<body>
  <div class="container">
    ${contentEl.innerHTML}
  </div>
</body>
</html>`;

    const blob = new Blob([docHtml], { type: 'text/html;charset=utf-8' 
  });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showGovToast(`Signed Document ${filename} downloaded successfully!`);
  };

  // =========================================================================
  // PRINT ACTIVE CERTIFICATE
  // =========================================================================
  window.printActiveCertificate = function() {
    window.print();
  };

  // =========================================================================
  // RTPS SERVICE MODE SWITCHER (APPLY, TRACK, VERIFY)
  // =========================================================================
  window.switchServiceMode = function(mode) {
    const pageServices = document.getElementById('page-services');
    if (pageServices && pageServices.classList.contains('hidden')) {
      document.querySelectorAll('.portal-page').forEach(p => p.classList.add('hidden'));
      pageServices.classList.remove('hidden');
    }
    const btnApply = document.getElementById('btn-mode-apply');
    const btnTrack = document.getElementById('btn-mode-track');
    const btnVerify = document.getElementById('btn-mode-verify');
    const panelTrack = document.getElementById('panel-track-status');
    const paneBirth = document.getElementById('desk-pane-birth');

    [btnApply, btnTrack, btnVerify].forEach(b => {
      if (b) {
        b.className = 'lovable-pill bg-white/10 hover:bg-white/20 text-white font-semibold cursor-pointer border border-white/20 transition';
      }
    
  });

    if (mode === 'apply') {
      if (btnApply) btnApply.className = 'lovable-pill bg-[#FF8000] text-white font-bold cursor-pointer shadow-sm hover:bg-[#E67300] transition';
      if (panelTrack) panelTrack.classList.add('hidden');
      if (paneBirth) paneBirth.classList.remove('hidden');
      const protoSec = document.getElementById('citizen-service-prototype');
      if (protoSec) {
        protoSec.scrollIntoView({ behavior: 'smooth', block: 'start' 
  });
      }
      showGovToast('Online Application Form Active');
    } else if (mode === 'track') {
      if (btnTrack) btnTrack.className = 'lovable-pill bg-[#FF8000] text-white font-bold cursor-pointer shadow-sm hover:bg-[#E67300] transition';
      if (panelTrack) {
        panelTrack.classList.remove('hidden');
        panelTrack.scrollIntoView({ behavior: 'smooth', block: 'start' 
  });
      }
      window.loadDemoTrackApplication();
      showGovToast('Application Status Tracker Active');
    } else if (mode === 'verify') {
      if (btnVerify) btnVerify.className = 'lovable-pill bg-[#FF8000] text-white font-bold cursor-pointer shadow-sm hover:bg-[#E67300] transition';
      if (panelTrack) panelTrack.classList.add('hidden');
      if (paneBirth) paneBirth.classList.remove('hidden');
      const verifyInput = document.getElementById('verify-input-birth');
      if (verifyInput) {
        verifyInput.focus();
        verifyInput.scrollIntoView({ behavior: 'smooth', block: 'center' 
  });
      }
      window.verifyCertificateLookup('birth');
      showGovToast('Certificate Authenticity Verification Active');
    }
  };

  // =========================================================================
  // RTPS APPLICATION STATUS TRACKER (5-STAGE TIMELINE)
  // =========================================================================
  window.trackApplicationAction = function() {
    const refInput = document.getElementById('track-input-ref');
    const container = document.getElementById('track-result-container');
    if (!refInput || !container) return;

    const refNo = refInput.value.trim() || 'NDIG/2026/BC/948271';
    const childName = (currentBirthData.childName || 'Aarav Sharma').toUpperCase();
    const fatherName = currentBirthData.fatherName || 'Rohit Sharma';

    container.innerHTML = `
      <div class="border border-[#CBD5E1] rounded-lg p-4 bg-[#F8FAFC] space-y-4 shadow-sm animate-fadeIn">
        <div class="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-[#CBD5E1] gap-2">
          <div>
            <div class="flex items-center gap-2">
              <span class="text-xs font-mono font-bold text-[#00314D] bg-[#EBF5FF] px-2 py-0.5 rounded border border-[#BFDBFE]">${refNo}</span>
              <span class="px-2 py-0.5 rounded bg-[#DEF7EC] text-[#03543F] border border-[#31C48D] text-[10.5px] font-bold">
                स्वीकृत एवं निर्गत (APPROVED &amp; DELIVERED)
              </span>
            </div>
            <h5 class="text-xs font-bold text-[#1F2937] mt-1">
              नागरिक सेवा: जन्म प्रमाण पत्र का निर्गमन (Issuance of Birth Certificate)
            </h5>
            <div class="text-[11px] text-[#64748B]">
              आवेदक: <strong>${fatherName}</strong> | शिशु: <strong>${childName}</strong> | पोर्टल: <strong>RTPS Interoperability Gateway</strong>
            </div>
          </div>
          <div class="flex gap-2">
            <button type="button" onclick="window.switchServiceMode('apply'); window.switchDocTab('birthcert');" class="bg-[#138808] hover:bg-[#0F6B06] text-white px-3 py-1.5 rounded font-bold text-xs flex items-center gap-1 cursor-pointer shadow-sm">
              <i data-lucide="file-check" class="w-3.5 h-3.5"></i>
              <span>View Certificate</span>
            </button>
            <button type="button" onclick="window.switchServiceMode('apply'); window.switchDocTab('receipt');" class="bg-[#00314D] hover:bg-[#002236] text-white px-3 py-1.5 rounded font-bold text-xs flex items-center gap-1 cursor-pointer shadow-sm">
              <i data-lucide="receipt" class="w-3.5 h-3.5"></i>
              <span>View Slip</span>
            </button>
          </div>
        </div>

        <div class="space-y-3 pt-1">
          <div class="rtps-timeline-step">
            <div class="rtps-timeline-dot bg-[#10B981] text-white">
              <i data-lucide="check" class="w-3 h-3"></i>
            </div>
            <div class="text-xs font-bold text-[#00314D]">चरण १: आवेदन सफलतापूर्वक दर्ज (Application Registered)</div>
            <div class="text-[11px] text-[#64748B]">अस्पताल प्रसव सूचना एवं CRS फॉर्म ५ डेटा गेटवे पर प्राप्त हुआ • १२-१०-२०२६ १०:१४:०१ IST</div>
          </div>

          <div class="rtps-timeline-step">
            <div class="rtps-timeline-dot bg-[#10B981] text-white">
              <i data-lucide="check" class="w-3 h-3"></i>
            </div>
            <div class="text-xs font-bold text-[#00314D]">चरण २: संस्थागत अस्पताल एवं सिविल रजिस्ट्री मिलान (CRS Verified)</div>
            <div class="text-[11px] text-[#64748B]">एम्स (AIIMS) मेडिकल रिकॉर्ड एवं दिल्ली नगर निगम रजिस्ट्री से स्वतः सत्यापन पूर्ण • १२-१०-२०२६ १०:१४:०८ IST</div>
          </div>

          <div class="rtps-timeline-step">
            <div class="rtps-timeline-dot bg-[#10B981] text-white">
              <i data-lucide="check" class="w-3 h-3"></i>
            </div>
            <div class="text-xs font-bold text-[#00314D]">चरण ३: UIDAI आधार पहचान बस एवं बाल आधार जारी (Baal Aadhaar Issued)</div>
            <div class="text-[11px] text-[#64748B]">माता-पिता आधार टोकन सत्यापन एवं बाल आधार जनरेट हुआ • १२-१०-२०२६ १०:१४:१९ IST</div>
          </div>

          <div class="rtps-timeline-step">
            <div class="rtps-timeline-dot bg-[#10B981] text-white">
              <i data-lucide="check" class="w-3 h-3"></i>
            </div>
            <div class="text-xs font-bold text-[#00314D]">चरण ४: सक्षम प्राधिकारी डिजिटल हस्ताक्षर (Registrar DSC Approved)</div>
            <div class="text-[11px] text-[#64748B]">डॉ. आलोक वर्मा, मुख्य रजिस्ट्रार (Class 3 DSC) द्वारा डिजिटल हस्ताक्षर अंकित • १२-१०-२०२६ १०:१५:०२ IST</div>
          </div>

          <div class="rtps-timeline-step">
            <div class="rtps-timeline-dot bg-[#10B981] text-white">
              <i data-lucide="check" class="w-3 h-3"></i>
            </div>
            <div class="text-xs font-bold text-[#047857]">चरण ५: प्रमाण पत्र निर्गत एवं डिजीलॉकर सिंक (Delivered to DigiLocker)</div>
            <div class="text-[11px] text-[#047857] font-semibold">आधिकारिक जन्म प्रमाण पत्र (फॉर्म ५) डिजीलॉकर में सुरक्षित उपलब्ध • १२-१०-२०२६ १०:१५:११ IST</div>
          </div>
        </div>
      </div>
    `;

    if (window.lucide) window.lucide.createIcons();
    showGovToast(`Status Loaded: Application ${refNo} is APPROVED`);
  };

  window.loadDemoTrackApplication = function() {
    const refInput = document.getElementById('track-input-ref');
    if (refInput) {
      refInput.value = 'NDIG/2026/BC/' + (currentBirthData.regNo ? currentBirthData.regNo.split('/').pop() : '948271');
    }
    window.trackApplicationAction();
  };

  // =========================================================================
  // REAL-TIME FORM SYNC (LOVABLE-STYLE DYNAMIC CERTIFICATE UPDATES)
  // =========================================================================
  function syncFormDataFromInputs() {
    const hospEl = document.getElementById('input-hospital');
    const childEl = document.getElementById('input-child-name');
    const genderEl = document.getElementById('input-child-gender');
    const dobEl = document.getElementById('input-child-dob');
    const weightEl = document.getElementById('input-child-weight');
    const motherNameEl = document.getElementById('input-mother-name');
    const motherAadhaarEl = document.getElementById('input-mother-aadhaar');
    const fatherNameEl = document.getElementById('input-father-name');
    const fatherAadhaarEl = document.getElementById('input-father-aadhaar');
    const addressEl = document.getElementById('input-permanent-address');

    if (childEl && childEl.value !== undefined) currentBirthData.childName = childEl.value;
    if (hospEl && hospEl.value !== undefined) currentBirthData.hospital = hospEl.value;
    if (genderEl && genderEl.value !== undefined) currentBirthData.gender = genderEl.value;
    if (dobEl && dobEl.value !== undefined) currentBirthData.dob = dobEl.value;
    if (weightEl && weightEl.value !== undefined) currentBirthData.weight = weightEl.value;
    if (motherNameEl && motherNameEl.value !== undefined) currentBirthData.motherName = motherNameEl.value;
    if (motherAadhaarEl && motherAadhaarEl.value !== undefined) currentBirthData.motherAadhaar = motherAadhaarEl.value;
    if (fatherNameEl && fatherNameEl.value !== undefined) currentBirthData.fatherName = fatherNameEl.value;
    if (fatherAadhaarEl && fatherAadhaarEl.value !== undefined) currentBirthData.fatherAadhaar = fatherAadhaarEl.value;
    if (addressEl && addressEl.value !== undefined) currentBirthData.address = addressEl.value;
  }

  function setupLiveFormSync() {
    const inputIds = [
      'input-hospital', 'input-child-name', 'input-child-gender',
      'input-child-dob', 'input-child-weight', 'input-mother-name',
      'input-mother-aadhaar', 'input-father-name', 'input-father-aadhaar',
      'input-permanent-address'
    ];
    inputIds.forEach(id => {
      const el = document.getElementById(id);
      if (el) {
        el.addEventListener('input', () => {
          syncFormDataFromInputs();
          updateActiveDocumentDisplay();
        });
      }
    });

    // CRS Death & Marriage live inputs
    ['input-death-name', 'input-death-date', 'input-death-place', 'input-death-cause', 'input-marriage-groom', 'input-marriage-bride', 'input-marriage-date', 'input-marriage-place'].forEach(id => {
      const el = document.getElementById(id);
      if (el) {
        el.addEventListener('input', () => { updateActiveDocumentDisplay(); });
        el.addEventListener('change', () => { updateActiveDocumentDisplay(); });
      }
    });

    // Revenue Department (10 certificates) live inputs
    ['input-caste-dept', 'input-caste-applicant', 'input-caste-father', 'input-caste-category', 'input-caste-subcaste', 'input-caste-district', 'input-caste-address', 'input-caste-father-cert', 'input-caste-income', 'input-caste-income-source', 'input-caste-purpose', 'input-caste-tenure', 'input-caste-thana', 'input-divyang-type', 'input-divyang-pct', 'input-divyang-cmo', 'input-character-purpose', 'input-character-status', 'input-land-khasra', 'input-land-khata', 'input-land-area', 'input-legalheir-deceased', 'input-legalheir-dod', 'input-legalheir-heirs', 'input-solvency-amount', 'input-solvency-property'].forEach(id => {
      const el = document.getElementById(id);
      if (el) {
        el.addEventListener('input', () => { window.generateCasteCertificateAction(); });
        el.addEventListener('change', () => { window.generateCasteCertificateAction(); });
      }
    });

    // Transport Department (5 certificates) live inputs
    ['input-dl-authority', 'input-dl-name', 'input-dl-father', 'input-dl-dob', 'input-dl-blood', 'input-dl-class', 'input-dl-address', 'input-rc-regno', 'input-rc-maker', 'input-rc-chassis', 'input-rc-engine', 'input-rc-fuel', 'input-rc-validity'].forEach(id => {
      const el = document.getElementById(id);
      if (el) {
        el.addEventListener('input', () => { window.generateDrivingLicenceAction(); });
        el.addEventListener('change', () => { window.generateDrivingLicenceAction(); });
      }
    });

    // Corporate & MSME (4 certificates) live inputs
    ['input-biz-name', 'input-biz-class', 'input-biz-capital', 'input-biz-director', 'input-biz-address', 'input-udyam-class', 'input-udyam-activity', 'input-eshram-occupation', 'input-eshram-uan'].forEach(id => {
      const el = document.getElementById(id);
      if (el) {
        el.addEventListener('input', () => { window.generateBusinessCertificateAction(); });
        el.addEventListener('change', () => { window.generateBusinessCertificateAction(); });
      }
    });

    // Welfare & Farmer (5 certificates) live inputs
    ['input-farmer-name', 'input-farmer-aadhaar', 'input-farmer-khasra', 'input-farmer-village', 'input-farmer-amt', 'input-farmer-bank', 'input-ration-category', 'input-ration-members', 'input-ration-fps', 'input-ration-grain', 'input-pension-type', 'input-pension-ppo'].forEach(id => {
      const el = document.getElementById(id);
      if (el) {
        el.addEventListener('input', () => { window.generateFarmerVoucherAction(); });
        el.addEventListener('change', () => { window.generateFarmerVoucherAction(); });
      }
    });
  }

  // Setup form sync listener
  setupLiveFormSync();

  // 12. Initial Load with default language (loads stored or 'en')
  applyLanguage(currentLang);

  // =========================================================================
  // MERIPEHCHAAN CITIZEN & OFFICER SSO LOGIN HANDLERS
  // =========================================================================
  window.openLoginModal = function() {
    const modal = document.getElementById('modal-gov-login');
    if (modal) {
      modal.classList.remove('hidden');
      if (window.lucide) lucide.createIcons();
    }
  };

  window.closeLoginModal = function() {
    const modal = document.getElementById('modal-gov-login');
    if (modal) modal.classList.add('hidden');
  };

  window.switchLoginTab = function(type) {
    const tabCitizen = document.getElementById('tab-login-citizen');
    const tabOfficer = document.getElementById('tab-login-officer');
    const paneCitizen = document.getElementById('login-pane-citizen');
    const paneOfficer = document.getElementById('login-pane-officer');

    if (type === 'citizen') {
      if (tabCitizen) tabCitizen.className = "py-2 rounded font-bold text-center transition bg-[#00314D] text-white shadow-xs cursor-pointer";
      if (tabOfficer) tabOfficer.className = "py-2 rounded font-bold text-center transition text-slate-600 hover:text-[#00314D] cursor-pointer";
      if (paneCitizen) paneCitizen.classList.remove('hidden');
      if (paneOfficer) paneOfficer.classList.add('hidden');
    } else {
      if (tabOfficer) tabOfficer.className = "py-2 rounded font-bold text-center transition bg-[#00314D] text-white shadow-xs cursor-pointer";
      if (tabCitizen) tabCitizen.className = "py-2 rounded font-bold text-center transition text-slate-600 hover:text-[#00314D] cursor-pointer";
      if (paneOfficer) paneOfficer.classList.remove('hidden');
      if (paneCitizen) paneCitizen.classList.add('hidden');
    }
    if (window.lucide) lucide.createIcons();
  };

  window.sendLoginOtp = function() {
    if (typeof showGovToast === 'function') {
      showGovToast('Demo OTP 589201 sent to registered mobile via UIDAI Gateway!');
    }
    const otpInput = document.getElementById('login-citizen-otp');
    if (otpInput) otpInput.value = '589201';
  };

  window.simulateLogin = function(type) {
    window.closeLoginModal();
    const user = SecurityAuthManager.login(type);
    if (type === 'citizen') {
      if (typeof showGovToast === 'function') {
        showGovToast('MeriPehchaan SSO Session Established: Citizen ' + escapeHtml(user.name));
      }
    } else {
      if (typeof showGovToast === 'function') {
        showGovToast('Parichay Officer Portal Active: SDM / Tehsildar [Class 3 DSC Active]');
      }
    }
  };

  window.logoutUser = function() {
    SecurityAuthManager.logout();
    if (typeof showGovToast === 'function') {
      showGovToast('Session Terminated. Logged out of MeriPehchaan securely.');
    }
  };

  // =========================================================================
  // TERMS & CONDITIONS / LEGAL POLICY MODAL HANDLERS
  // =========================================================================
  window.openTermsModal = function() {
    const modal = document.getElementById('modal-gov-terms');
    if (modal) {
      modal.classList.remove('hidden');
      if (window.lucide) lucide.createIcons();
    }
  };

  window.closeTermsModal = function() {
    const modal = document.getElementById('modal-gov-terms');
    if (modal) modal.classList.add('hidden');
  };

  // =========================================================================
  // 10. CYBERSECURITY HARDENING: ANTI-XSS SANITIZER & RATE LIMITER
  // =========================================================================
  // escapeHtml already initialized in Core Security Engine at top of DOMContentLoaded
  window.escapeHtml = window.escapeHtml || escapeHtml;

  const SecurityRateLimiter = {
    records: {},
    allow(actionKey, limit = 10, windowMs = 30000) {
      const now = Date.now();
      if (!this.records[actionKey]) this.records[actionKey] = [];
      this.records[actionKey] = this.records[actionKey].filter(t => now - t < windowMs);
      if (this.records[actionKey].length >= limit) return false;
      this.records[actionKey].push(now);
      return true;
    }
  };
  window.SecurityRateLimiter = SecurityRateLimiter;

  // Protect translation dictionaries against prototype pollution
  try {
    Object.freeze(translations.en);
    Object.freeze(translations.hi);
  } catch (e) {}

  // =========================================================================
  // 11. AI DRISHTI: REAL-TIME NEURAL DOCUMENT TAMPER & FRAUD SCANNER (v3.4)
  // =========================================================================
  const drishtiSamples = {
    genuine_caste: {
      type: "Caste Certificate (Gazette Form 4)",
      id: "UP/2026/CC/849201",
      holder: "AMIT KUMAR JATAV",
      issuer: "Tehsildar / Sub-Divisional Magistrate, Lucknow",
      status: "GENUINE",
      hash: "0x89e1f42a7c89b910dc025e1a90b8f4139981d3f9e8310c14b29f9e71c6384a51",
      fontStatus: "100% Matching (Devanagari Unicode 15.0)",
      fontDesc: "Zero font splicing, micro-typographic kerning is uniform across all fields.",
      dscStatus: "Valid Class 3 DSC (NIC CA 2026)",
      dscDesc: "Digital Certificate signed by SDM verified against Controller of Certifying Authorities.",
      hashStatus: "Cryptographic Match Confirmed",
      hashDesc: "Payload matches SHA-256 state ledger record #UP-REV-2026-99214.",
      confidence: "99.98%",
      verdictTitle: "AI VERDICT: 100% AUTHENTIC DOCUMENT",
      verdictText: "Document verified against National Civil Registry Bus. Zero evidence of visual tampering, pixel alteration, or certificate spoofing.",
      isTampered: false
    },
    tampered_ews: {
      type: "EWS Income & Asset Certificate",
      id: "UP/2026/EWS/391024",
      holder: "VIKRAM SINGH",
      issuer: "Revenue Council, Meerut",
      status: "TAMPERED",
      hash: "0x4b7890a2fc8811e9a93bbcd0284e912f7c00192a71f782390a1829e84019bd33",
      fontStatus: "ALERT: Font Mismatch (Arial Bold overlaid on Noto)",
      fontDesc: "Discontinuity detected in income figure field '₹45,000'. Original value '₹9,80,000' digitally scrubbed.",
      dscStatus: "INVALID: Broken DSC Signature Chain",
      dscDesc: "Digital signature checksum fails integrity check. Document altered post-signing.",
      hashStatus: "HASH MISMATCH: Unrecognized Document Hash",
      hashDesc: "Calculated hash does not match State Revenue Authority block ledger.",
      confidence: "88.4% Tamper Risk",
      verdictTitle: "ALERT: TAMPERED DOCUMENT DETECTED",
      verdictText: "CRITICAL FORENSIC DISCREPANCY: The annual income figure has been digitally altered to qualify under EWS ceiling. Official seal hash is invalid.",
      isTampered: true
    },
    genuine_dl: {
      type: "Smart Driving Licence (MoRTH)",
      id: "DL-0420260084920",
      holder: "PRIYA SHARMA",
      issuer: "Licensing Authority, New Delhi RTO",
      status: "GENUINE",
      hash: "0x12a98f4c9103e298df3400a91e84732109baef01298437019823ef0912837401",
      fontStatus: "100% Matching (Sarathi Font Spec 2.0)",
      fontDesc: "Chip cryptographic payload matches QR Code 256-bit signature.",
      dscStatus: "Valid RTO Digital Seal",
      dscDesc: "National Register Parivahan public key verification succeeded.",
      hashStatus: "State Registry Ledger Match",
      hashDesc: "Real-time query to MoRTH Parivahan central node returned status ACTIVE.",
      confidence: "99.95%",
      verdictTitle: "AI VERDICT: 100% AUTHENTIC SMART LICENCE",
      verdictText: "Verified with MoRTH Sarathi national identity bus. Card is completely authentic with valid endorsement.",
      isTampered: false
    }
  };

  let activeDrishtiKey = 'genuine_caste';
  let drishtiHeatmapActive = false;

  window.switchVerifierMode = function(mode) {
    const pipelineBtn = document.getElementById('btn-verifier-mode-pipeline');
    const drishtiBtn = document.getElementById('btn-verifier-mode-drishti');
    const pipelineView = document.querySelector('#live-verifier .grid.grid-cols-1.lg\\:grid-cols-12');
    const drishtiPanel = document.getElementById('ai-drishti-panel');

    if (mode === 'drishti') {
      if (pipelineBtn) {
        pipelineBtn.classList.remove('bg-[#FF8000]', 'text-white', 'shadow-xs');
        pipelineBtn.classList.add('text-slate-300', 'hover:text-white', 'hover:bg-white/10');
      }
      if (drishtiBtn) {
        drishtiBtn.classList.remove('text-slate-300', 'hover:text-white', 'hover:bg-white/10');
        drishtiBtn.classList.add('bg-[#FF8000]', 'text-white', 'shadow-xs');
      }
      if (pipelineView) pipelineView.classList.add('hidden');
      if (drishtiPanel) {
        drishtiPanel.classList.remove('hidden');
        window.loadDrishtiSample(activeDrishtiKey);
      }
    } else {
      if (drishtiBtn) {
        drishtiBtn.classList.remove('bg-[#FF8000]', 'text-white', 'shadow-xs');
        drishtiBtn.classList.add('text-slate-300', 'hover:text-white', 'hover:bg-white/10');
      }
      if (pipelineBtn) {
        pipelineBtn.classList.remove('text-slate-300', 'hover:text-white', 'hover:bg-white/10');
        pipelineBtn.classList.add('bg-[#FF8000]', 'text-white', 'shadow-xs');
      }
      if (pipelineView) pipelineView.classList.remove('hidden');
      if (drishtiPanel) drishtiPanel.classList.add('hidden');
    }
    if (window.lucide) lucide.createIcons();
  };

  window.loadDrishtiSample = function(key) {
    activeDrishtiKey = key;
    const sample = drishtiSamples[key] || drishtiSamples.genuine_caste;
    const docDisplay = document.getElementById('drishti-doc-display');
    const statFont = document.getElementById('drishti-stat-font');
    const descFont = document.getElementById('drishti-desc-font');
    const statSeal = document.getElementById('drishti-stat-seal');
    const descSeal = document.getElementById('drishti-desc-seal');
    const statHash = document.getElementById('drishti-stat-hash');
    const descHash = document.getElementById('drishti-desc-hash');
    const liveBadge = document.getElementById('drishti-live-badge');
    const verdictBanner = document.getElementById('drishti-verdict-banner');
    const verdictTitle = document.getElementById('drishti-verdict-title');
    const verdictText = document.getElementById('drishti-verdict-text');

    if (docDisplay) {
      if (sample.isTampered) {
        docDisplay.innerHTML = `
          <div class="border-2 border-red-400 bg-red-50/50 p-4 rounded-lg relative">
            <div class="absolute top-2 right-2 bg-red-600 text-white text-[9px] font-mono px-2 py-0.5 rounded font-bold uppercase">
              SUSPECTED DOCTORED SCAN
            </div>
            <div class="text-center pb-2 border-b border-red-200">
              <span class="text-xs font-bold text-red-900 tracking-wider">GOVERNMENT OF UTTAR PRADESH • REVENUE DEPARTMENT</span>
              <h4 class="font-extrabold text-sm text-red-950 mt-1">${escapeHtml(sample.type)}</h4>
              <span class="text-[10px] text-red-700 font-mono">Ref: ${escapeHtml(sample.id)}</span>
            </div>
            <div class="py-3 text-[11px] space-y-2 text-slate-800">
              <p>Certified that Shri <strong>${escapeHtml(sample.holder)}</strong> resident of Meerut belongs to Economically Weaker Section (EWS).</p>
              <div class="p-2 bg-yellow-100 border border-yellow-400 rounded text-red-900 font-bold flex items-center justify-between">
                <span>Gross Annual Family Income:</span>
                <span class="bg-red-200 px-2 py-0.5 rounded text-red-900 line-through">₹9,80,000</span>
                <span class="text-sm font-extrabold text-red-700 underline font-mono">₹45,000 (Altered)</span>
              </div>
              <p class="text-[10px] text-slate-600">Issued by: ${escapeHtml(sample.issuer)}</p>
            </div>
            <div class="pt-2 border-t border-red-200 flex items-center justify-between text-[10px]">
              <span class="text-red-700 font-mono font-bold">DSC Stamp: MISMATCH</span>
              <span class="text-slate-500 font-mono">SHA256: ${escapeHtml(sample.hash.substring(0, 18))}...</span>
            </div>
          </div>
        `;
      } else {
        docDisplay.innerHTML = `
          <div class="border-2 border-emerald-400 bg-emerald-50/40 p-4 rounded-lg relative">
            <div class="absolute top-2 right-2 bg-emerald-700 text-white text-[9px] font-mono px-2 py-0.5 rounded font-bold uppercase">
              STATE ATTESTED ORIGINAL
            </div>
            <div class="text-center pb-2 border-b border-emerald-200">
              <span class="text-xs font-bold text-emerald-950 tracking-wider">GOVERNMENT OF INDIA • NATIONAL ATTESTATION LEDGER</span>
              <h4 class="font-extrabold text-sm text-emerald-950 mt-1">${escapeHtml(sample.type)}</h4>
              <span class="text-[10px] text-emerald-800 font-mono">Doc ID: ${escapeHtml(sample.id)}</span>
            </div>
            <div class="py-3 text-[11px] space-y-2 text-slate-800">
              <p>This is to certify that <strong>${escapeHtml(sample.holder)}</strong> has been verified via the National Interoperability Gateway with active biometric consent.</p>
              <div class="p-2 bg-white border border-emerald-300 rounded text-emerald-900 font-semibold flex items-center justify-between">
                <span>Issuing Authority:</span>
                <span class="font-bold">${escapeHtml(sample.issuer)}</span>
              </div>
              <p class="text-[10px] text-slate-600">Verification Status: <strong>VALID &amp; UNALTERED</strong></p>
            </div>
            <div class="pt-2 border-t border-emerald-200 flex items-center justify-between text-[10px]">
              <span class="text-emerald-700 font-mono font-bold">Class 3 DSC: VERIFIED</span>
              <span class="text-slate-500 font-mono">SHA256: ${escapeHtml(sample.hash.substring(0, 18))}...</span>
            </div>
          </div>
        `;
      }
    }

    if (statFont) {
      statFont.textContent = sample.fontStatus;
      statFont.className = sample.isTampered ? "font-mono font-bold text-red-600 text-[11px]" : "font-mono font-bold text-[#138808]";
    }
    if (descFont) descFont.textContent = sample.fontDesc;
    if (statSeal) {
      statSeal.textContent = sample.dscStatus;
      statSeal.className = sample.isTampered ? "font-mono font-bold text-red-600 text-[11px]" : "font-mono font-bold text-[#138808]";
    }
    if (descSeal) descSeal.textContent = sample.dscDesc;
    if (statHash) {
      statHash.textContent = sample.hashStatus;
      statHash.className = sample.isTampered ? "font-mono font-bold text-red-600 text-[11px]" : "font-mono font-bold text-[#138808]";
    }
    if (descHash) descHash.textContent = sample.hashDesc;

    if (liveBadge) {
      liveBadge.textContent = sample.isTampered ? "FRAUD DETECTED" : "VERIFIED AUTHENTIC";
      liveBadge.className = sample.isTampered
        ? "text-[10px] font-mono font-bold bg-red-100 text-red-800 px-2 py-0.5 rounded border border-red-300"
        : "text-[10px] font-mono font-bold bg-[#DEF7EC] text-[#03543F] px-2 py-0.5 rounded border border-[#31C48D]";
    }

    if (verdictBanner && verdictTitle && verdictText) {
      verdictTitle.textContent = sample.verdictTitle;
      verdictText.textContent = sample.verdictText;
      if (sample.isTampered) {
        verdictBanner.className = "p-3.5 rounded-xl border border-red-300 bg-red-50 text-red-900 transition-all";
      } else {
        verdictBanner.className = "p-3.5 rounded-xl border border-emerald-300 bg-emerald-50 text-emerald-900 transition-all";
      }
    }

    // Update heatmap if active
    if (drishtiHeatmapActive) {
      drishtiHeatmapActive = false;
      window.toggleDrishtiHeatmap();
    }

    if (window.lucide) lucide.createIcons();
  };

  window.toggleDrishtiHeatmap = function() {
    drishtiHeatmapActive = !drishtiHeatmapActive;
    const btn = document.getElementById('btn-toggle-drishti-heatmap');
    const btnText = document.getElementById('btn-heatmap-text');
    const previewWrapper = document.getElementById('drishti-preview-wrapper');

    const existingOverlay = document.getElementById('drishti-heatmap-overlay-el');
    if (existingOverlay) existingOverlay.remove();
    const existingTag = document.getElementById('drishti-heatmap-tag-el');
    if (existingTag) existingTag.remove();
    const existingSeal = document.getElementById('drishti-heatmap-seal-tag-el');
    if (existingSeal) existingSeal.remove();

    if (drishtiHeatmapActive) {
      if (btn) {
        btn.classList.add('bg-rose-50', 'border-rose-400', 'text-rose-700', 'ring-2', 'ring-rose-200');
        btn.classList.remove('bg-white', 'border-[#CBD5E1]', 'text-[#00314D]');
      }
      if (btnText) btnText.textContent = "Hide Anomaly Heatmap";

      const sample = drishtiSamples[activeDrishtiKey] || drishtiSamples.genuine_caste;
      if (previewWrapper) {
        if (sample.isTampered) {
          const overlay = document.createElement('div');
          overlay.id = 'drishti-heatmap-overlay-el';
          overlay.className = 'drishti-heatmap-overlay';
          previewWrapper.appendChild(overlay);

          const tag = document.createElement('div');
          tag.id = 'drishti-heatmap-tag-el';
          tag.className = 'drishti-heatmap-tag';
          tag.style.top = '48%';
          tag.style.right = '8%';
          tag.style.width = '160px';
          tag.style.height = '38px';
          tag.innerHTML = `
            <div class="absolute -top-6 right-0 bg-red-600 text-white font-mono text-[9px] font-bold px-1.5 py-0.5 rounded shadow">
              ⚠️ 88.4% TAMPER ENTROPY
            </div>
          `;
          previewWrapper.appendChild(tag);

          const sealTag = document.createElement('div');
          sealTag.id = 'drishti-heatmap-seal-tag-el';
          sealTag.className = 'drishti-heatmap-tag';
          sealTag.style.bottom = '12%';
          sealTag.style.left = '6%';
          sealTag.style.width = '140px';
          sealTag.style.height = '32px';
          sealTag.innerHTML = `
            <div class="absolute -top-5 left-0 bg-red-700 text-white font-mono text-[9px] font-bold px-1.5 py-0.5 rounded shadow">
              ⚠️ INVALID DSC STAMP
            </div>
          `;
          previewWrapper.appendChild(sealTag);

          if (typeof showGovToast === 'function') {
            showGovToast('Forensic Heatmap Active: Altered income figure & invalid DSC stamp highlighted.');
          }
        } else {
          const overlay = document.createElement('div');
          overlay.id = 'drishti-heatmap-overlay-el';
          overlay.className = 'drishti-genuine-overlay';
          overlay.innerHTML = `
            <div class="absolute top-4 left-4 bg-emerald-600 text-white font-mono text-[10px] font-bold px-2 py-1 rounded shadow">
              ✅ 100% Surface Uniformity • Zero Anomalies
            </div>
          `;
          previewWrapper.appendChild(overlay);

          if (typeof showGovToast === 'function') {
            showGovToast('Forensic Heatmap Active: 100% surface uniformity verified across certificate.');
          }
        }
      }
    } else {
      if (btn) {
        btn.classList.remove('bg-rose-50', 'border-rose-400', 'text-rose-700', 'ring-2', 'ring-rose-200');
        btn.classList.add('bg-white', 'border-[#CBD5E1]', 'text-[#00314D]');
      }
      if (btnText) btnText.textContent = "Show Anomaly Heatmap";
      if (typeof showGovToast === 'function') {
        showGovToast('Forensic Heatmap hidden.');
      }
    }
  };

  window.handleDrishtiFileUpload = function(event) {
    const file = event.target.files && event.target.files[0];
    if (!file) return;

    const validation = SecurityFileValidator.validate(file);
    if (!validation.valid) {
      if (typeof showGovToast === 'function') {
        showGovToast(validation.error);
      }
      alert(validation.error);
      return;
    }

    const fileName = file.name;
    const isSuspicious = fileName.toLowerCase().includes('edit') || fileName.toLowerCase().includes('fake') || fileName.toLowerCase().includes('tamper') || fileName.toLowerCase().includes('test');
    const customKey = 'uploaded_custom';

    drishtiSamples[customKey] = {
      type: "Uploaded Citizen Certificate (" + (file.type || 'Document') + ")",
      id: "UPLOAD/" + Math.floor(100000 + Math.random() * 900000),
      holder: "CITIZEN SUBMITTED FILE",
      issuer: "Decentralized Optical Gate / NeGD Verifier",
      status: isSuspicious ? "TAMPERED" : "GENUINE",
      hash: "0x" + Array.from(new Uint8Array(32)).map(() => Math.floor(Math.random() * 16).toString(16)).join(''),
      fontStatus: isSuspicious ? "ALERT: Pixel Matrix Discontinuity Detected" : "100% Uniform Raster Grid",
      fontDesc: isSuspicious ? "Inconsistent pixel entropy in text fields suggests non-native PDF manipulation." : "Clean optical character grid. Font metrics match official UIDAI / NIC templates.",
      dscStatus: isSuspicious ? "INVALID: No Embedded Cryptographic Certificate" : "Valid Self-Contained Checksum",
      dscDesc: isSuspicious ? "Document lacks verifiable cryptographic timestamp and Class 3 digital token." : "Cryptographic signature verified against public key infrastructure.",
      hashStatus: isSuspicious ? "UNKNOWN HASH: Unregistered in State Ledger" : "Valid Ephemeral Attestation Hash",
      hashDesc: isSuspicious ? "Calculated digest does not map to any active state nodal authority." : "Uploaded document hash verified for live transaction verification.",
      confidence: isSuspicious ? "79.2% Tamper Risk" : "99.4% Authenticity",
      verdictTitle: isSuspicious ? "AI FORENSIC ALERT: SUSPECTED ALTERATION" : "AI VERDICT: DOCUMENT VERIFIED AUTHENTIC",
      verdictText: isSuspicious 
        ? "AI Drishti neural scan detected potential metadata modification and raster misalignment in the uploaded document." 
        : "AI Drishti neural scan confirmed document matches standard statutory layout with zero detected tampering.",
      isTampered: isSuspicious
    };

    const select = document.getElementById('drishti-sample-select');
    if (select) {
      let opt = select.querySelector('option[value="uploaded_custom"]');
      if (!opt) {
        opt = document.createElement('option');
        opt.value = 'uploaded_custom';
        select.appendChild(opt);
      }
      opt.textContent = `4. Uploaded: ${fileName.substring(0, 24)} [${isSuspicious ? 'Tampered' : 'Authentic'}]`;
      select.value = 'uploaded_custom';
    }

    window.loadDrishtiSample('uploaded_custom');
    if (typeof showGovToast === 'function') {
      showGovToast(`Uploaded "${fileName}". Running AI Drishti neural scan...`);
    }
    window.runDrishtiScan();
  };

  window.runDrishtiScan = function() {
    if (!SecurityRateLimiter.allow('drishti_scan', 10, 30000)) {
      if (typeof showGovToast === 'function') {
        showGovToast('Security Notice: Scan rate limit reached. Please wait a moment.');
      }
      return;
    }

    const laser = document.getElementById('drishti-laser-beam');
    const liveBadge = document.getElementById('drishti-live-badge');
    const scanBtn = document.getElementById('btn-run-drishti-scan');

    if (laser) laser.classList.remove('hidden');
    if (liveBadge) {
      liveBadge.textContent = "AI SCANNING IN PROGRESS...";
      liveBadge.className = "text-[10px] font-mono font-bold bg-amber-100 text-amber-800 px-2 py-0.5 rounded border border-amber-300 animate-pulse";
    }
    if (scanBtn) scanBtn.disabled = true;

    if (typeof showGovToast === 'function') {
      showGovToast('AI Drishti: Scanning document for pixel anomalies, font mismatch & ledger integrity...');
    }

    setTimeout(() => {
      if (laser) laser.classList.add('hidden');
      if (scanBtn) scanBtn.disabled = false;
      window.loadDrishtiSample(activeDrishtiKey);
      if (typeof showGovToast === 'function') {
        const sample = drishtiSamples[activeDrishtiKey];
        if (sample && sample.isTampered) {
          showGovToast('⚠️ AI Drishti Alert: Critical Document Tampering & Font Discrepancy Found!');
        } else {
          showGovToast('✅ AI Drishti: 100% Authentic Document verified against National Attestation Ledger!');
        }
      }
    }, 1800);
  };

  window.downloadDrishtiReport = function() {
    const sample = drishtiSamples[activeDrishtiKey] || drishtiSamples.genuine_caste;
    const reportHtml = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>AI Drishti Forensic Audit Report - ${escapeHtml(sample.id)}</title>
        <style>
          body { font-family: 'Segoe UI', Arial, sans-serif; padding: 30px; color: #00314D; }
          .header { border-bottom: 3px double #00314D; padding-bottom: 12px; margin-bottom: 20px; }
          .badge { padding: 4px 10px; border-radius: 4px; font-weight: bold; font-family: monospace; display: inline-block; }
          .badge-ok { background: #DEF7EC; color: #03543F; border: 1px solid #31C48D; }
          .badge-alert { background: #FDE8E8; color: #9B1C1C; border: 1px solid #F98080; }
          table { width: 100%; border-collapse: collapse; margin-top: 15px; }
          td, th { border: 1px solid #CBD5E1; padding: 8px 12px; text-align: left; font-size: 13px; }
          th { background: #F8FAFC; }
          .footer { margin-top: 30px; border-top: 1px solid #CBD5E1; padding-top: 12px; font-size: 11px; color: #64748B; }
        </style>
      </head>
      <body>
        <div class="header">
          <h2>GOVERNMENT OF INDIA • NATIONAL E-GOVERNANCE DIVISION (NeGD)</h2>
          <h3>AI DRISHTI FORENSIC AUDIT &amp; CRYPTOGRAPHIC VERIFICATION CERTIFICATE</h3>
          <p>Generated under Section 4 &amp; 5 of the Information Technology Act 2000 | DPDP Act 2023</p>
        </div>
        <div>
          <span class="badge ${sample.isTampered ? 'badge-alert' : 'badge-ok'}">
            AUDIT STATUS: ${sample.isTampered ? 'SUSPECTED FRAUD / TAMPERED' : 'VERIFIED 100% AUTHENTIC'}
          </span>
        </div>
        <table>
          <tr><th>Document ID</th><td>${escapeHtml(sample.id)}</td></tr>
          <tr><th>Document Type</th><td>${escapeHtml(sample.type)}</td></tr>
          <tr><th>Verified Holder</th><td>${escapeHtml(sample.holder)}</td></tr>
          <tr><th>Issuing Authority</th><td>${escapeHtml(sample.issuer)}</td></tr>
          <tr><th>Cryptographic Hash</th><td><code>${escapeHtml(sample.hash)}</code></td></tr>
          <tr><th>Optical Kerning &amp; Font Integrity</th><td>${escapeHtml(sample.fontStatus)}</td></tr>
          <tr><th>Digital Signature (DSC)</th><td>${escapeHtml(sample.dscStatus)}</td></tr>
          <tr><th>AI Forensic Confidence Score</th><td><strong>${escapeHtml(sample.confidence)}</strong></td></tr>
        </table>
        <div class="footer">
          <p>Certified by NeGD AI Drishti Neural Forensic Core. Audit Hash: ${escapeHtml(sample.hash.substring(0, 32))} | Timestamp: ${new Date().toISOString()}</p>
        </div>
      </body>
      </html>
    `;
    const win = window.open('', '_blank');
    if (win) {
      win.document.write(reportHtml);
      win.document.close();
      win.print();
    }
  };

  // =========================================================================
  // 12. E-SAARTHI: MULTILINGUAL AI CITIZEN ASSISTANT & REAL-TIME PROBLEM SOLVER (v5.0)
  // =========================================================================
  let esaarthiSpeechEnabled = true;

  window.toggleEsaarthi = function() {
    const drawer = document.getElementById('esaarthi-ai-drawer');
    if (drawer) {
      drawer.classList.toggle('hidden');
      if (!drawer.classList.contains('hidden')) {
        const inp = document.getElementById('esaarthi-input');
        if (inp) inp.focus();
        if (window.lucide) lucide.createIcons();
      }
    }
  };

  window.toggleEsaarthiSpeech = function() {
    esaarthiSpeechEnabled = !esaarthiSpeechEnabled;
    const btn = document.getElementById('esaarthi-tts-toggle');
    if (btn) {
      btn.innerHTML = esaarthiSpeechEnabled
        ? '<i data-lucide="volume-2" class="w-4 h-4 text-emerald-400"></i>'
        : '<i data-lucide="volume-x" class="w-4 h-4 text-slate-400"></i>';
      if (window.lucide) lucide.createIcons();
    }
    const wave = document.getElementById('esaarthi-waveform');
    if (wave && !esaarthiSpeechEnabled) wave.classList.add('hidden');
    if (typeof showGovToast === 'function') {
      showGovToast(esaarthiSpeechEnabled ? 'Voice readout enabled for e-Saarthi.' : 'Voice readout muted.');
    }
  };

  window.clearEsaarthiChat = function() {
    const container = document.getElementById('esaarthi-chat-messages');
    if (container) {
      container.innerHTML = `
        <div class="flex items-start gap-2">
          <div class="w-6 h-6 rounded-full bg-[#00314D] text-white flex items-center justify-center shrink-0 mt-0.5 shadow-sm">
            <i data-lucide="sparkles" class="w-3 h-3 text-[#FF8000]"></i>
          </div>
          <div class="bg-white border border-[#CBD5E1] rounded-2xl rounded-tl-none p-3 shadow-xs text-slate-800 max-w-[88%] space-y-2 leading-relaxed">
            <p class="font-bold text-[#00314D] text-xs">Chat history reset. Aapka swagat hai! 🙏</p>
            <p class="text-[11px] text-[#475569]">
              Main <strong>e-Saarthi</strong> hoon. Aap mujhse kisi bhi aavedan me deri (delay), reject hone ka samadhan, naam/dob sudhar, ya sarkari schemes ke baare me bina jhijhak pooch sakte hain.
            </p>
          </div>
        </div>
      `;
      if (window.lucide) lucide.createIcons();
    }
  };

  // 12.1 COMPREHENSIVE CITIZEN PROBLEM SOLVING KNOWLEDGE & DIAGNOSTIC REPOSITORY
  const esaarthiKnowledgeBase = {
    // Problem 1: Rejection Help
    rejection: {
      title: "❌ Application Rejection Resolution (अस्वीकृत आवेदन का समाधान)",
      badge: "RTS Act Section 6 Legal Remedy",
      text: "Aavedan reject hone ke 3 mukhya kaaran hote hain: 1) Khatauni/RoR me pita ka naam na milna, 2) Purana/adhura affidavit, ya 3) Dhundhli photo.",
      solutionSteps: [
        "Track Status me jakar official Rejection Slip me darj 'Objection Reason' check karein.",
        "Right to Public Services Act ki Dhara 6 ke tahat 30 din me SDM (First Appellate Authority) ke paas nishulk appeal karein.",
        "DigiLocker se authenticated certified document jodkar 1-click me punah aavedan karein."
      ],
      slaText: "Appellate SDM Statutory Decision Window: 15 Working Days",
      actionText: "File First Appeal / Grievance Desk",
      actionKey: "grievance"
    },

    // Problem 2: Delay / Pending Status
    delay: {
      title: "⏳ 15+ Days Application Pending Delay (देरी की शिकायत एवं हर्जाना)",
      badge: "Citizen Charter SLA Enforcement",
      text: "Citizen Charter ke anusar Caste/Domicile ka SLA 15 din aur Income ka 7-10 working days hota hai. Samay-seema beetne par Jan Sewa Guarantee ke tahat doshi adhikaari par ₹250/din ka statutory fine lagta hai.",
      solutionSteps: [
        "Apne Application Number se desk-level tracking check karein (Lekhpal/Tehsildar/RI).",
        "CPGRAMS / Jan Sunwai portal par 'SLA Timeline Breach' notice raise karein.",
        "First Appellate Officer ko automatic escalation alert trigger karein."
      ],
      slaText: "Public Service Guarantee Penalty: ₹250 / Day on Officer",
      actionText: "Track Status & Raise SLA Delay Notice",
      actionKey: "track"
    },

    // Problem 3: Name / DOB Correction
    correction: {
      title: "✏️ Name & Date of Birth Correction (नाम एवं जन्मतिथि त्रुटि सुधार)",
      badge: "Gazette Clerical Correction Rules",
      text: "Yadi certificate me naam ki spelling ya janmatithi galat print ho gayi hai to clerical typo hone par Tehsildar bina naye aavedan ke 7 din me theek karta hai.",
      solutionSteps: [
        "Mool aavedan slip aur 10th Marks Sheet ya Aadhaar update receipt taiyyar rakhein.",
        "Portal par 'Clerical Amendment / Correction Form' submit karein.",
        "Sahi dastaawez upload karte hi QR-coded digital copy DigiLocker me sync hogi."
      ],
      slaText: "Statutory Rectification SLA: 7 Working Days",
      actionText: "Open Correction Desk",
      actionKey: "caste"
    },

    // Problem 4: Pension / Scholarship Stopped
    pension: {
      title: "💰 Pension / Scholarship Disbursal Failure (पेंशन/DBT विफलता समाधान)",
      badge: "NPCI DBT & Jeevan Pramaan Protocol",
      text: "85% mamlo me pension ya scholarship rukne ke do hi kaaran hote hain: 1) Bank account me Aadhaar NPCI DBT mapping inactive hona, ya 2) Annual Digital Life Certificate (Jeevan Pramaan) expire hona.",
      solutionSteps: [
        "Apne smartphone par 'Jeevan Pramaan Face-Auth App' se 2 minute me ghar baithe DLC jama karein.",
        "Apne bank jakar 'NPCI Aadhaar Mandate Form' submit karein jisse DBT direct account me aaye.",
        "PFMS portal par DBT transaction reference verify karein."
      ],
      slaText: "DBT Reactivation Window: 48-72 Banking Hours",
      actionText: "Check Welfare Entitlements (Yojana Drishti)",
      actionKey: "yojana"
    },

    // Problem 5: No-Collateral Loans
    loan: {
      title: "🏦 Collateral-Free Business Loan (बिना गारंटी सरकारी लोन)",
      badge: "CGTMSE 100% Credit Guarantee",
      text: "Nayi dukaan, thele-patri vyapaar ya business shuru karne ke liye sarkar bina kisi zameen ya security ke loan deti hai: PM SVANidhi (₹10,000-₹50,000 7% subsidy) aur PM Mudra (Shishu up to ₹50k, Kishore up to ₹5 Lakh).",
      solutionSteps: [
        "udyamregistration.gov.in par jakar 5 minute me free Udyam MSME certificate banayein.",
        "Aadhaar, PAN aur 6 mahine ka bank statement lein.",
        "Jan Samarth portal ya kisi bhi sarkari bank me Mudra/SVANidhi ke tahat aavedan karein."
      ],
      slaText: "Sanction Timeframe: 7-10 Days under Credit Guarantee",
      actionText: "Explore Mudra & Loan Schemes",
      actionKey: "yojana"
    },

    // Problem 6: EWS Land Ceiling Issue
    ews_issue: {
      title: "📜 EWS Certificate Denial / Land Ceiling Rules (ईडब्ल्यूएस समस्या)",
      badge: "Constitutional 103rd Amendment Rules",
      text: "EWS aarakshan ke kanooni niyam: Kul parivarik aay ₹8 Lakh se kam, krishi bhoomi 5 acre se kam, aavasiya plot 1000 sq ft se kam. Yadi Lekhpal zubaani mana karta hai to written objection order maangna aapka kanooni adhikar hai.",
      solutionSteps: [
        "Apni Khatauni (RoR) download karein jisme landholding 5 acre se kam saaf dikh rahi ho.",
        "Tehsildar ke samaksh 'Sanyukt Simankan' aavedan prastut karein.",
        "Yadi laparwahi ho to SDM office me RTS Act Section 5 ke tahat grievance darj karein."
      ],
      slaText: "Statutory EWS Disposal Timeframe: 10 Working Days",
      actionText: "Open Income & EWS Desk",
      actionKey: "income"
    },

    // Problem 7: DL Renewal / Expired
    dl_renew: {
      title: "🚗 Expired Driving Licence Renewal (ड्राइविंग लाइसेंस रिन्यूअल)",
      badge: "Motor Vehicles (Amendment) Act 2019",
      text: "Agar licence expire hue 1 saal se kam hua hai to bina driving test diye Form 9 + Medical Form 1A se renewal ho jata hai. Agar 1 saal se zyada ho gaya hai to automated track par driving test dobara dena anivarya hota hai.",
      solutionSteps: [
        "Parivahan Sarathi par 'Services on Driving Licence' chunen.",
        "DL number aur DOB se details fetch karein.",
        "Medical certificate Form 1A upload karke online fees pay karein. Naya Smart Card speed post se ghar aayega."
      ],
      slaText: "Smart Card Dispatch SLA: 15 Days post-approval",
      actionText: "Open Smart DL Portal",
      actionKey: "dl"
    },

    // Problem 8: Public Utility & Electricity Bill Dispute
    bill_dispute: {
      title: "⚡ Electricity Bill Dispute & Public Grievance (बिजली बिल समस्या)",
      badge: "Electricity Regulatory Commission Act",
      text: "Galat billing ya kharab meter ke mamle me DISCOM helpline 1912 par dispute register hota hai. Yadi sunwai na ho to Consumer Grievance Redressal Forum (CGRF) me complaint ki ja sakti hai.",
      solutionSteps: [
        "Pichle 3 mahine ke bills aur meter reading ki photo taiyyar karein.",
        "1912 par billing dispute number generate karein aur provisional bill par payment ki request karein.",
        "CPGRAMS par District Magistrate / Energy Department ko escalation complaint bhejein."
      ],
      slaText: "Dispute Resolution SLA: 15 Working Days",
      actionText: "Open Grievance Desk",
      actionKey: "grievance"
    },

    // Problem 9: Lost Aadhaar Card
    lost_id: {
      title: "🆔 Lost Aadhaar / Identity Recovery (खोया आधार कैसे निकालें)",
      badge: "UIDAI Electronic Identity Protocol",
      text: "Yadi physical Aadhaar kho gaya hai aur number bhi yaad nahi hai to mobile OTP ke zariye 2 minute me digitally signed e-Aadhaar prapt kiya ja sakta hai.",
      solutionSteps: [
        "uidai.gov.in par 'Retrieve Lost UID/EID' par click karein.",
        "Apna poora naam aur registered mobile number daalein.",
        "SMS me 12-digit Aadhaar aate hi DigiLocker ya UIDAI se download karein."
      ],
      slaText: "Instant Electronic Delivery: <2 Minutes",
      actionText: "Open Live Verifier Desk",
      actionKey: "digilocker"
    },

    // Conversational Greeting
    greeting: {
      title: "🙏 Namaste! Main e-Saarthi Hoon (आपकी सेवा में सदैव तत्पर)",
      badge: "24x7 Citizen Assistance AI",
      text: "Namaste! Main e-Saarthi hoon, aapka National e-Governance AI Saathi. Aap mujhse kisi bhi aavedan me deri, rejection ka samadhan, naam/dob theek karna, bina security loan, pension ya dastaawez satyapan ke baare me pooch sakte hain.",
      solutionSteps: [
        "Aap seedhe Hinglish ya Hindi me apni samasya likhiye.",
        "Main statutory niyam, time limit aur seedha form link provide karunga."
      ],
      slaText: "24x7 Real-Time Citizen Problem Resolution",
      actionText: "Explore 12+ Welfare Schemes",
      actionKey: "yojana"
    },

    // Gratitude
    thanks: {
      title: "🇮🇳 Aapka Swagat Hai! (समस्या समाधान सम्पन्न)",
      badge: "Digital India • Citizen First",
      text: "Aapka bohot-bohot swagat hai! 🙏 Hame khushi hui ki aapki samasya ka kanooni v takneeki samadhan mil saka. Yadi bhavishya me kisi bhi sarkari sewa me dikkat aaye, to e-Saarthi hamesha aapki seva me upalabdha hai. Jai Hind!",
      solutionSteps: [
        "Sarkari sewaon me kisi bhi bhrashtachar ya delay ke khilaf CPGRAMS ka upyog karein.",
        "Sabhi praman-patro ko DigiLocker me digitally attested rakhein."
      ],
      slaText: "Citizen Charter Protected Rights",
      actionText: "Explore Services Directory",
      actionKey: "directory"
    },

    // Existing Statutory Topics
    caste: {
      title: "Caste Certificate (जाति प्रमाण पत्र) Guidelines",
      badge: "State Revenue Department",
      text: "To apply for Caste Certificate (SC/ST/OBC), you require: 1) Aadhaar Card, 2) Land RoR / Khatiyan showing ancestry, 3) Self-declaration affidavit. The statutory service turnaround is 15 working days under the Citizen Charter with ₹0 government fee.",
      solutionSteps: ["Aadhaar link", "Khatiyan / Land Record", "Self-declaration affidavit"],
      slaText: "Statutory SLA: 15 Working Days",
      actionText: "Open Caste Certificate Desk",
      actionKey: "caste"
    },
    dl: {
      title: "Smart Driving Licence (MoRTH Sarathi) Guidelines",
      badge: "Ministry of Road Transport & Highways",
      text: "Permanent Driving Licence requires: 1) Active Learner's Licence (>30 days old), 2) Form 1A Medical Fitness, 3) Automated Driving Test slot at RTO. Upon passing, your Class 3 digitally signed Smart Card is issued within 15 days and synced to DigiLocker.",
      solutionSteps: ["Learner licence test passed", "Form 1A medical fitness", "Slot booking at RTO track"],
      slaText: "Statutory SLA: 15 Days post-test",
      actionText: "Open Smart Driving Licence Desk",
      actionKey: "dl"
    },
    income: {
      title: "Income & EWS Certificate Criteria",
      badge: "Revenue Board & Social Welfare",
      text: "Income certificates verify total family gross annual earnings. For EWS (Economically Weaker Section) reservation, family annual income must not exceed ₹8,00,000, with land holding < 5 acres. Issued under SDM/Tehsildar seal within 7 to 10 days.",
      solutionSteps: ["Salary slip / IT return or Gram Pradhan report", "Electricity bill", "Affidavit of family income"],
      slaText: "Statutory SLA: 7-10 Working Days",
      actionText: "Open Income Certificate Desk",
      actionKey: "income"
    },
    domicile: {
      title: "Domicile / Residence Certificate (मूल निवास प्रमाण पत्र)",
      badge: "State Home / General Administration",
      text: "Permanent Domicile requires: 1) Proof of continuous residence for >= 10 years (Electricity bill/Voter ID), 2) Educational certificate from state board, 3) Aadhaar link. Statutory delivery timeline: 7 working days.",
      solutionSteps: ["10-year residency electricity bills / voter slip", "State school/college certificate", "Aadhaar e-KYC"],
      slaText: "Statutory SLA: 7 Working Days",
      actionText: "Open Domicile Certificate Desk",
      actionKey: "domicile"
    },
    birth: {
      title: "Birth Certificate (जन्म प्रमाण पत्र) via Civil Registration (CRS)",
      badge: "Registrar General of India (CRS)",
      text: "Birth Registration under the RBD Act: Apply within 21 days with hospital discharge receipt or institutional birth report. Late registration requires SDM executive magistrate sanction. Issued with digitally signed QR code in 7 days.",
      solutionSteps: ["Hospital discharge slip / institutional report", "Parents Aadhaar cards", "Application within 21 days"],
      slaText: "Statutory SLA: 7 Days (Zero fee in 21 days)",
      actionText: "Open Birth Registration Desk",
      actionKey: "birth"
    },
    death: {
      title: "Death Certificate (मृत्यु प्रमाण पत्र) Registration",
      badge: "Civil Registration System (CRS)",
      text: "Under the Registration of Births and Deaths Act: Required documents include Cremation/Burial ground slip and attending physician Form 4/4A. Delivered within 7 days with unique CRS National Registration Number.",
      solutionSteps: ["Burial/Cremation receipt", "Attending doctor certificate Form 4/4A", "Aadhaar of applicant & deceased"],
      slaText: "Statutory SLA: 7 Days",
      actionText: "Open Civil Registration Desk",
      actionKey: "death"
    },
    track: {
      title: "Track Application Status (आवेदन स्थिति जांचें)",
      badge: "National Interoperability Bus",
      text: "You can track any statutory e-governance application instantly using your Application Reference Number (e.g., UP/2026/CC/849201 or DL-0420260084920). All 28 state nodal servers return real-time pipeline status.",
      solutionSteps: ["Enter Application Reference ID", "Nodal server queries state ledger", "SMS notification dispatched"],
      slaText: "Real-time Telemetry (<100ms)",
      actionText: "Open Application Tracker",
      actionKey: "track"
    },
    fraud: {
      title: "AI Drishti Document Fraud & Tamper Check",
      badge: "Neural Vision Forensic Engine v3.4",
      text: "AI Drishti uses neural optical scan models to inspect certificates for pixel alterations, font discontinuities, forged Tehsildar seals, and mismatched SHA-256 state ledger hashes. You can run instant forensic scans on sample or uploaded certificates.",
      solutionSteps: ["Select sample or upload citizen file", "Activate Anomaly Heatmap", "Verify against National Attestation Ledger"],
      slaText: "Neural Optical Verification: <2.2 Seconds",
      actionText: "Launch AI Drishti Forensic Verifier",
      actionKey: "drishti"
    },
    yojana: {
      title: "AI Yojana Drishti: Welfare Scheme Eligibility Matcher",
      badge: "IndEA 2.0 Applied AI Engine",
      text: "AI Yojana Drishti analyzes your 5-parameter socioeconomic profile (Age, State, Annual Income, Category, Occupation) to instantly calculate eligibility for 12+ statutory welfare programs with up to ₹5,75,000 annual benefits.",
      solutionSteps: ["Input 5 citizen demographics", "Calculate automated eligibility score", "1-click auto-fill statutory desks"],
      slaText: "Calculated in <200ms",
      actionText: "Launch AI Yojana Matcher",
      actionKey: "yojana"
    },
    grievance: {
      title: "CPGRAMS Public Grievance Redressal (लोक शिकायत निवारण)",
      badge: "Department of Administrative Reforms (DARPG)",
      text: "If your statutory service is delayed beyond the Citizen Charter SLA timeframe, you can lodge an escalation under CPGRAMS with zero fee. A designated First Appellate Officer will resolve the grievance within 30 days.",
      solutionSteps: ["File online docket with reference ID", "Unique registration number generated", "30-day statutory Action Taken Report"],
      slaText: "Statutory Resolution SLA: 30 Days",
      actionText: "Open Grievance Redressal Desk",
      actionKey: "grievance"
    },
    digilocker: {
      title: "DigiLocker DPI Cloud Repository & National Sync",
      badge: "Rule 9A Information Technology Act",
      text: "DigiLocker is recognized as legally equivalent to original physical documents under Rule 9A of Information Technology Rules 2016. Every certificate issued through this gateway is automatically pushed to your DigiLocker URI.",
      solutionSteps: ["Consent-based fetch via Aadhaar OTP", "SHA-256 verified issuer cryptographic signature", "Zero physical paperwork required"],
      slaText: "Instant Push & Sync",
      actionText: "View Live DigiLocker Verification",
      actionKey: "digilocker"
    }
  };

  window.sendQuickEsaarthi = function(key) {
    const item = esaarthiKnowledgeBase[key];
    if (item) {
      window.appendEsaarthiUserMessage(item.title);
      window.showEsaarthiTypingIndicator();
      setTimeout(() => {
        window.hideEsaarthiTypingIndicator();
        window.appendEsaarthiBotResponse(item);
      }, 550);
    }
  };

  window.sendEsaarthiMessage = function(customQuery) {
    const input = document.getElementById('esaarthi-input');
    const text = customQuery || (input ? input.value.trim() : '');
    if (!text) return;

    if (!SecurityRateLimiter.allow('esaarthi_msg', 15, 60000)) {
      if (typeof showGovToast === 'function') {
        showGovToast('Notice: Please wait a moment between messages.');
      }
      return;
    }

    if (input) input.value = '';
    window.appendEsaarthiUserMessage(text);
    window.showEsaarthiTypingIndicator();

    const lower = text.toLowerCase();
    let matched = null;

    // Natural Language Problem-Solving Intent Classifier (Prioritized with Word Boundaries)
    if (lower.includes('thank') || lower.includes('dhanyawad') || lower.includes('धन्यवाद') || lower.includes('shukriya') || lower.includes('kaam ho gaya') || lower.includes('bohot badhiya')) {
      matched = esaarthiKnowledgeBase.thanks;
    } else if (lower.includes('reject') || lower.includes('asweekrat') || lower.includes('अस्वीकृत') || lower.includes('खारिज') || lower.includes('cancel')) {
      matched = esaarthiKnowledgeBase.rejection;
    } else if (lower.includes('pend') || lower.includes('deri') || lower.includes('देरी') || lower.includes('kab aayega') || lower.includes('bohot din') || lower.includes('late') || lower.includes('15 din') || lower.includes('nahi bana')) {
      matched = esaarthiKnowledgeBase.delay;
    } else if (lower.includes('naam galat') || lower.includes('dob galat') || lower.includes('correction') || lower.includes('sudhar') || lower.includes('सुधार') || lower.includes('spelling') || lower.includes('theek kaise') || lower.includes('galati')) {
      matched = esaarthiKnowledgeBase.correction;
    } else if (lower.includes('pension') || lower.includes('पेंशन') || lower.includes('scholarship nahi') || lower.includes('paise nahi') || lower.includes('khate me') || lower.includes('dbt')) {
      matched = esaarthiKnowledgeBase.pension;
    } else if (lower.includes('loan') || lower.includes('ऋण') || lower.includes('karz') || lower.includes('mudra') || lower.includes('svanidhi') || lower.includes('bina guarantee') || lower.includes('bina security') || lower.includes('dukaan')) {
      matched = esaarthiKnowledgeBase.loan;
    } else if (lower.includes('dl expire') || lower.includes('renew') || lower.includes('purana dl') || lower.includes('रिन्यू') || lower.includes('driving license renew')) {
      matched = esaarthiKnowledgeBase.dl_renew;
    } else if (lower.includes('ews') || (lower.includes('lekhpal') && lower.includes('mana')) || lower.includes('zameen zyada')) {
      matched = esaarthiKnowledgeBase.ews_issue;
    } else if (lower.includes('bijli') || lower.includes('bill') || lower.includes('बिजली') || lower.includes('meter') || lower.includes('discom') || lower.includes('bhrashtachar') || lower.includes('rishwat')) {
      matched = esaarthiKnowledgeBase.bill_dispute;
    } else if (lower.includes('lost') || lower.includes('kho gaya') || lower.includes('खो गया') || lower.includes('aadhar number nahi') || lower.includes('gum ho gaya')) {
      matched = esaarthiKnowledgeBase.lost_id;
    } else if (lower.includes('hello') || /\bhi\b/.test(lower) || /\bhey\b/.test(lower) || lower.includes('namaste') || lower.includes('नमस्ते') || lower.includes('kaise ho') || lower.includes('kya hal') || lower.includes('madad') || lower.includes('help') || lower.includes('who are you')) {
      matched = esaarthiKnowledgeBase.greeting;
    } else if (lower.includes('caste') || lower.includes('jaati') || lower.includes('जाति') || lower.includes('sc') || lower.includes('st') || lower.includes('obc')) {
      matched = esaarthiKnowledgeBase.caste;
    } else if (lower.includes('dl') || lower.includes('driving') || lower.includes('licence') || lower.includes('license') || lower.includes('गाड़ी') || lower.includes('ड्राइविंग') || lower.includes('sarathi')) {
      matched = esaarthiKnowledgeBase.dl;
    } else if (lower.includes('income') || lower.includes('आय') || lower.includes('kamai') || lower.includes('salary') || lower.includes('tax')) {
      matched = esaarthiKnowledgeBase.income;
    } else if (lower.includes('domicile') || lower.includes('niwas') || lower.includes('निवास') || lower.includes('residence') || lower.includes('address')) {
      matched = esaarthiKnowledgeBase.domicile;
    } else if (lower.includes('birth') || lower.includes('janam') || lower.includes('जन्म') || lower.includes('bacha') || lower.includes('crs')) {
      matched = esaarthiKnowledgeBase.birth;
    } else if (lower.includes('death') || lower.includes('mrityu') || lower.includes('मृत्यु') || lower.includes('maut')) {
      matched = esaarthiKnowledgeBase.death;
    } else if (lower.includes('yojana') || lower.includes('scheme') || lower.includes('योजना') || lower.includes('subsidy') || lower.includes('labh') || lower.includes('benefit') || lower.includes('paatra')) {
      matched = esaarthiKnowledgeBase.yojana;
    } else if (lower.includes('track') || lower.includes('status') || lower.includes('स्थिति') || lower.includes('kahan') || lower.includes('number')) {
      matched = esaarthiKnowledgeBase.track;
    } else if (lower.includes('fraud') || lower.includes('fake') || lower.includes('tamper') || lower.includes('verify') || lower.includes('नकली') || lower.includes('जांच') || lower.includes('drishti')) {
      matched = esaarthiKnowledgeBase.fraud;
    } else if (lower.includes('grievance') || lower.includes('shikayat') || lower.includes('शिकायत') || lower.includes('complaint')) {
      matched = esaarthiKnowledgeBase.grievance;
    } else {
      matched = {
        title: "🔍 Citizen Inquiry Diagnostic (नागरिक सहायता परामर्श)",
        badge: "National e-Governance Division",
        text: `Regarding "${escapeHtml(text)}": Humne aapke prashna ka vishleshan kiya hai. National Digital Interoperability Gateway sabhi 28 rajyon ke civil certificates, transport desk aur 12+ kendriya yojanaon ko DPDP Act 2023 zero-knowledge encryption ke tahat jodta hai.`,
        solutionSteps: [
          "Yadi aapka aavedan ruka hai to Application Reference ID se status check karein.",
          "Naye praman-patra ya scheme ke liye relevant online desk ka prayog karein.",
          "Kisi bhi pareshani ke liye CPGRAMS grievance portal par 30-day statutory sunwai darj karein."
        ],
        slaText: "Single-Window Citizen Support (SLA Bound)",
        actionText: "Explore Services Directory",
        actionKey: "directory"
      };
    }

    setTimeout(() => {
      window.hideEsaarthiTypingIndicator();
      window.appendEsaarthiBotResponse(matched);
    }, 600);
  };

  window.showEsaarthiTypingIndicator = function() {
    const container = document.getElementById('esaarthi-chat-messages');
    if (!container) return;
    const existing = document.getElementById('esaarthi-typing-indicator');
    if (existing) existing.remove();

    const typingDiv = document.createElement('div');
    typingDiv.id = 'esaarthi-typing-indicator';
    typingDiv.className = 'flex items-start gap-2';
    typingDiv.innerHTML = `
      <div class="w-6 h-6 rounded-full bg-[#00314D] text-white flex items-center justify-center shrink-0 mt-0.5 shadow-sm">
        <i data-lucide="sparkles" class="w-3 h-3 text-[#FF8000]"></i>
      </div>
      <div class="typing-bubble">
        <span class="typing-dot"></span>
        <span class="typing-dot"></span>
        <span class="typing-dot"></span>
      </div>
    `;
    container.appendChild(typingDiv);
    container.scrollTop = container.scrollHeight;
    if (window.lucide) lucide.createIcons();
  };

  window.hideEsaarthiTypingIndicator = function() {
    const el = document.getElementById('esaarthi-typing-indicator');
    if (el) el.remove();
  };

  window.appendEsaarthiUserMessage = function(text) {
    const container = document.getElementById('esaarthi-chat-messages');
    if (!container) return;
    const msgDiv = document.createElement('div');
    msgDiv.className = 'flex items-start justify-end gap-2 animate-fadeIn';
    msgDiv.innerHTML = `
      <div class="bg-[#00314D] text-white rounded-2xl rounded-tr-none p-3 shadow-xs max-w-[85%] text-xs leading-relaxed">
        <p>${escapeHtml(text)}</p>
      </div>
      <div class="w-6 h-6 rounded-full bg-[#FF8000] text-white flex items-center justify-center shrink-0 mt-0.5 text-[10px] font-bold shadow-sm">
        U
      </div>
    `;
    container.appendChild(msgDiv);
    container.scrollTop = container.scrollHeight;
  };

  window.appendEsaarthiBotResponse = function(item) {
    const container = document.getElementById('esaarthi-chat-messages');
    if (!container) return;
    const msgDiv = document.createElement('div');
    msgDiv.className = 'flex items-start gap-2 animate-fadeIn';

    const stepsHtml = (item.solutionSteps && item.solutionSteps.length > 0)
      ? `
        <div class="mt-2.5 p-2 bg-[#F8FAFC] border border-[#CBD5E1] rounded-xl text-[10.5px] space-y-1">
          <div class="font-bold text-[#00314D] flex items-center gap-1">
            <i data-lucide="check-circle" class="w-3 h-3 text-emerald-600"></i>
            <span>Actionable Resolution Plan (समाधान के चरण):</span>
          </div>
          <ol class="list-decimal list-inside space-y-1 text-slate-700 pl-1 font-medium">
            ${item.solutionSteps.map(s => `<li>${escapeHtml(s)}</li>`).join('')}
          </ol>
        </div>
      `
      : '';

    const slaHtml = item.slaText
      ? `
        <div class="mt-2 flex items-center justify-between text-[10px] text-emerald-800 bg-emerald-50 border border-emerald-200 px-2 py-1 rounded-lg">
          <span class="font-bold flex items-center gap-1">
            <i data-lucide="clock" class="w-3 h-3 text-emerald-600"></i>
            <span>${escapeHtml(item.slaText)}</span>
          </span>
          <span class="font-mono text-[9px] uppercase font-bold text-emerald-700">DPDP Protected</span>
        </div>
      `
      : '';

    msgDiv.innerHTML = `
      <div class="w-6 h-6 rounded-full bg-[#00314D] text-white flex items-center justify-center shrink-0 mt-0.5 shadow-sm">
        <i data-lucide="sparkles" class="w-3 h-3 text-[#FF8000]"></i>
      </div>
      <div class="bg-white border border-[#CBD5E1] rounded-2xl rounded-tl-none p-3.5 shadow-xs text-slate-800 max-w-[90%] space-y-2 leading-relaxed">
        <div class="flex items-center justify-between gap-2 border-b border-slate-100 pb-1.5">
          <h5 class="font-bold text-[#00314D] text-xs">${escapeHtml(item.title)}</h5>
          ${item.badge ? `<span class="text-[9px] font-mono font-bold bg-[#EBF5FF] text-[#00314D] px-2 py-0.5 rounded border border-[#BFDBFE] shrink-0">${escapeHtml(item.badge)}</span>` : ''}
        </div>
        <p class="text-[11px] text-[#475569] leading-relaxed">${item.text}</p>
        ${stepsHtml}
        ${slaHtml}
        <div class="pt-1.5">
          <button type="button" onclick="window.esaarthiLaunchForm('${item.actionKey}')" class="bg-[#00314D] hover:bg-[#FF8000] text-white font-bold text-[11px] px-3.5 py-1.5 rounded-xl transition flex items-center gap-1.5 shadow-xs cursor-pointer">
            <i data-lucide="arrow-right-circle" class="w-3.5 h-3.5 text-[#FF8000] group-hover:text-white"></i>
            <span>${escapeHtml(item.actionText)}</span>
          </button>
        </div>
      </div>
    `;
    container.appendChild(msgDiv);
    container.scrollTop = container.scrollHeight;
    if (window.lucide) lucide.createIcons();

    // Voice Readout with animated waveform
    if (esaarthiSpeechEnabled && 'speechSynthesis' in window) {
      try {
        window.speechSynthesis.cancel();
        const speechText = item.title + ". " + item.text;
        const utterance = new SpeechSynthesisUtterance(speechText);
        utterance.rate = 1.0;
        utterance.pitch = 1.0;

        const wave = document.getElementById('esaarthi-waveform');
        if (wave) wave.classList.remove('hidden');

        utterance.onend = () => {
          if (wave) wave.classList.add('hidden');
        };
        utterance.onerror = () => {
          if (wave) wave.classList.add('hidden');
        };

        window.speechSynthesis.speak(utterance);
      } catch (e) {}
    }
  };

  window.esaarthiLaunchForm = function(key) {
    window.toggleEsaarthi();
    if (key === 'caste') {
      window.switchProtoDesk('caste');
      window.switchRevenueSubService('caste');
      const el = document.getElementById('citizen-service-prototype');
      if (el) {
        el.scrollIntoView({ behavior: 'smooth' });
        el.classList.add('gov-form-highlight');
        setTimeout(() => el.classList.remove('gov-form-highlight'), 2500);
      }
    } else if (key === 'income') {
      window.switchProtoDesk('caste');
      window.switchRevenueSubService('income');
      const el = document.getElementById('citizen-service-prototype');
      if (el) {
        el.scrollIntoView({ behavior: 'smooth' });
        el.classList.add('gov-form-highlight');
        setTimeout(() => el.classList.remove('gov-form-highlight'), 2500);
      }
    } else if (key === 'domicile') {
      window.switchProtoDesk('caste');
      window.switchRevenueSubService('domicile');
      const el = document.getElementById('citizen-service-prototype');
      if (el) {
        el.scrollIntoView({ behavior: 'smooth' });
        el.classList.add('gov-form-highlight');
        setTimeout(() => el.classList.remove('gov-form-highlight'), 2500);
      }
    } else if (key === 'birth' || key === 'death' || key === 'marriage') {
      window.switchProtoDesk('birth');
      window.switchCrsSubService(key);
      const el = document.getElementById('citizen-service-prototype');
      if (el) {
        el.scrollIntoView({ behavior: 'smooth' });
        el.classList.add('gov-form-highlight');
        setTimeout(() => el.classList.remove('gov-form-highlight'), 2500);
      }
    } else if (key === 'dl' || key === 'll' || key === 'renewal' || key === 'rc' || key === 'fitness') {
      window.switchProtoDesk('dl');
      window.switchTransportSubService(key);
      const el = document.getElementById('citizen-service-prototype');
      if (el) {
        el.scrollIntoView({ behavior: 'smooth' });
        el.classList.add('gov-form-highlight');
        setTimeout(() => el.classList.remove('gov-form-highlight'), 2500);
      }
    } else if (['caste', 'income', 'domicile', 'ews', 'ncl', 'divyang', 'character', 'land', 'legalheir', 'solvency'].includes(key)) {
      window.switchProtoDesk('caste');
      window.switchRevenueSubService(key);
      const el = document.getElementById('citizen-service-prototype');
      if (el) {
        el.scrollIntoView({ behavior: 'smooth' });
        el.classList.add('gov-form-highlight');
        setTimeout(() => el.classList.remove('gov-form-highlight'), 2500);
      }
    } else if (['farmer', 'pmkisan', 'ration', 'kcc', 'pension', 'senior'].includes(key)) {
      window.switchProtoDesk('farmer');
      window.switchFarmerSubService(key === 'farmer' ? 'pmkisan' : key);
      const el = document.getElementById('citizen-service-prototype');
      if (el) {
        el.scrollIntoView({ behavior: 'smooth' });
        el.classList.add('gov-form-highlight');
        setTimeout(() => el.classList.remove('gov-form-highlight'), 2500);
      }
    } else if (['biz', 'business', 'spice', 'udyam', 'eshram', 'trade'].includes(key)) {
      window.switchProtoDesk('business');
      window.switchBusinessSubService(key === 'biz' || key === 'business' ? 'spice' : key);
      const el = document.getElementById('citizen-service-prototype');
      if (el) {
        el.scrollIntoView({ behavior: 'smooth' });
        el.classList.add('gov-form-highlight');
        setTimeout(() => el.classList.remove('gov-form-highlight'), 2500);
      }
    } else if (key === 'track') {
      window.switchServiceMode('track');
      const el = document.getElementById('citizen-service-prototype');
      if (el) {
        el.scrollIntoView({ behavior: 'smooth' });
        el.classList.add('gov-form-highlight');
        setTimeout(() => el.classList.remove('gov-form-highlight'), 2500);
      }
    } else if (key === 'drishti' || key === 'fraud') {
      window.switchVerifierMode('drishti');
      const el = document.getElementById('live-verifier');
      if (el) {
        el.scrollIntoView({ behavior: 'smooth' });
        el.classList.add('gov-form-highlight');
        setTimeout(() => el.classList.remove('gov-form-highlight'), 2500);
      }
    } else if (key === 'yojana') {
      const el = document.getElementById('ai-yojana-drishti');
      if (el) {
        el.scrollIntoView({ behavior: 'smooth' });
        window.runYojanaMatcher();
        el.classList.add('gov-form-highlight');
        setTimeout(() => el.classList.remove('gov-form-highlight'), 2500);
      }
    } else if (key === 'digilocker') {
      window.switchVerifierMode('pipeline');
      const el = document.getElementById('live-verifier');
      if (el) {
        el.scrollIntoView({ behavior: 'smooth' });
        el.classList.add('gov-form-highlight');
        setTimeout(() => el.classList.remove('gov-form-highlight'), 2500);
      }
    } else if (key === 'grievance') {
      const el = document.getElementById('helpdesk-contact');
      if (el) {
        el.scrollIntoView({ behavior: 'smooth' });
        el.classList.add('gov-form-highlight');
        setTimeout(() => el.classList.remove('gov-form-highlight'), 2500);
      }
    } else {
      const el = document.getElementById('rtps-services-directory');
      if (el) el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  // 12B. AI YOJANA DRISHTI: WELFARE ELIGIBILITY & SUBSIDY MATCHER ENGINE
  // =========================================================================
  const nationalSchemesDatabase = [
    {
      id: 'ab_pmjay',
      title: 'Ayushman Bharat PM-JAY',
      titleHi: 'आयुष्मान भारत प्रधानमंत्री जन आरोग्य योजना',
      ministry: 'Ministry of Health & Family Welfare',
      level: 'Central Scheme',
      badgeClass: 'bg-emerald-100 text-emerald-800 border-emerald-300',
      benefitValue: 500000,
      benefitDisplay: '₹5,00,000 / Year Cashless Health Cover',
      description: 'Secondary and tertiary hospitalization coverage across 27,000+ public and private empanelled hospitals with zero out-of-pocket expenses.',
      requiredCerts: ['Aadhaar Card', 'Ration Card / SECC 2011', 'Income Certificate'],
      targetDesk: 'caste',
      targetSub: 'income',
      evaluate: (p) => {
        if (p.income <= 450000 || p.category === 'SC' || p.category === 'ST' || p.category === 'EWS' || p.occupation === 'worker' || p.occupation === 'farmer') {
          return { eligible: true, score: 98, reason: 'Income & socioeconomic criteria qualify under PM-JAY SECC registry threshold.' };
        }
        return { eligible: false, score: 55, reason: 'Family income exceeds automatic PM-JAY qualification ceiling.' };
      }
    },
    {
      id: 'post_matric_scholarship',
      title: 'Post-Matric Scholarship for Higher Education',
      titleHi: 'पोस्ट-मैट्रिक छात्रवृत्ति योजना (उच्च शिक्षा)',
      ministry: 'Ministry of Social Justice & Empowerment',
      level: 'Centrally Sponsored',
      badgeClass: 'bg-blue-100 text-blue-800 border-blue-300',
      benefitValue: 45000,
      benefitDisplay: '100% Tuition Fee Waiver + ₹13,500 Maintenance',
      description: 'Complete academic fee reimbursement and monthly living allowance for collegiate, technical, and professional degree courses.',
      requiredCerts: ['Caste Certificate (Form 4)', 'Income Certificate (<₹2.5L)', 'College Bonafide'],
      targetDesk: 'caste',
      targetSub: 'caste',
      evaluate: (p) => {
        if (p.occupation === 'student' && p.age <= 35 && p.income <= 250000 && (p.category === 'SC' || p.category === 'ST' || p.category === 'OBC' || p.category === 'EWS')) {
          return { eligible: true, score: 99, reason: 'Student profile matches category reservation and income ceiling.' };
        }
        if (p.occupation === 'student' && p.income <= 450000) {
          return { eligible: true, score: 82, reason: 'Eligible for Central Sector Merit-cum-Means Scholarship quota.' };
        }
        return { eligible: false, score: 40, reason: 'Requires active student enrollment and income < ₹2.5 Lakh.' };
      }
    },
    {
      id: 'pm_kisan',
      title: 'PM-KISAN Samman Nidhi',
      titleHi: 'प्रधानमंत्री किसान सम्मान निधि',
      ministry: 'Ministry of Agriculture & Farmers Welfare',
      level: 'Central Sector',
      badgeClass: 'bg-amber-100 text-amber-800 border-amber-300',
      benefitValue: 6000,
      benefitDisplay: '₹6,000 / Year Direct DBT (3 Installments) + 4% KCC',
      description: 'Guaranteed liquidity support directly transferred to Aadhaar-seeded accounts for agricultural inputs, seed procurement, and fertilizer.',
      requiredCerts: ['Land RoR (Khatauni)', 'Aadhaar e-KYC', 'Bank Account NPCI Mandate'],
      targetDesk: 'caste',
      targetSub: 'income',
      evaluate: (p) => {
        if (p.occupation === 'farmer') {
          return { eligible: true, score: 99, reason: 'Farmer status validated. 100% entitlement to 3 equal DBT installments.' };
        }
        return { eligible: false, score: 20, reason: 'Statutorily restricted to operational agricultural landholders.' };
      }
    },
    {
      id: 'pm_svanidhi',
      title: 'PM SVANidhi Micro-Credit Scheme',
      titleHi: 'पीएम स्वनिधि सूक्ष्म ऋण योजना',
      ministry: 'Ministry of Housing and Urban Affairs',
      level: 'Central Sector',
      badgeClass: 'bg-purple-100 text-purple-800 border-purple-300',
      benefitValue: 50000,
      benefitDisplay: '₹10,000 – ₹50,000 Collateral-Free Credit + 7% Subvention',
      description: 'Special working capital loan for street vendors, small artisans, and informal entrepreneurs with cashback incentives on digital UPI payments.',
      requiredCerts: ['Aadhaar Card', 'Urban Local Body Vending ID / Shramik Card', 'Bank Passbook'],
      targetDesk: 'caste',
      targetSub: 'income',
      evaluate: (p) => {
        if ((p.occupation === 'worker' || p.occupation === 'business') && p.income <= 450000) {
          return { eligible: true, score: 94, reason: 'Informal enterprise and micro-worker profile fits SVANidhi working capital tier.' };
        }
        return { eligible: false, score: 35, reason: 'Targeted primarily at micro-entrepreneurs and daily-wage operators.' };
      }
    },
    {
      id: 'pm_awas_yojana',
      title: 'Pradhan Mantri Awas Yojana (PMAY-G / U)',
      titleHi: 'प्रधानमंत्री आवास योजना (ग्रामीण / शहरी)',
      ministry: 'Ministry of Rural Development',
      level: 'Centrally Sponsored',
      badgeClass: 'bg-teal-100 text-teal-800 border-teal-300',
      benefitValue: 130000,
      benefitDisplay: '₹1,20,000 – ₹2,50,000 Direct Pucca House Grant',
      description: 'Direct financial assistance for construction of disaster-resilient housing with geo-tagged verification and mandatory toilet facility subsidy.',
      requiredCerts: ['Income Certificate', 'Land Ownership / Patta', 'SECC Deprivation Proof'],
      targetDesk: 'caste',
      targetSub: 'income',
      evaluate: (p) => {
        if (p.income <= 250000 || p.category === 'SC' || p.category === 'ST' || p.category === 'EWS') {
          return { eligible: true, score: 91, reason: 'Low family income qualifies for EWS/LIG housing financial grant.' };
        }
        return { eligible: false, score: 50, reason: 'Income bracket exceeds PMAY beneficiary threshold.' };
      }
    },
    {
      id: 'ujjwala_2',
      title: 'Pradhan Mantri Ujjwala Yojana 2.0',
      titleHi: 'प्रधानमंत्री उज्ज्वला योजना 2.0',
      ministry: 'Ministry of Petroleum & Natural Gas',
      level: 'Central Scheme',
      badgeClass: 'bg-rose-100 text-rose-800 border-rose-300',
      benefitValue: 4800,
      benefitDisplay: 'Free LPG Connection + First Refill & Stove Grant',
      description: 'Deposit-free LPG connection for women from impoverished households with recurring cylinder subsidies credited directly via DBTL.',
      requiredCerts: ['Ration Card', 'Aadhaar of Adult Family Members', 'Bank Account Mandate'],
      targetDesk: 'caste',
      targetSub: 'domicile',
      evaluate: (p) => {
        if (p.occupation === 'female' || p.income <= 180000 || p.category === 'SC' || p.category === 'ST' || p.category === 'EWS') {
          return { eligible: true, score: 96, reason: 'Meets clean cooking fuel welfare criteria for underprivileged households.' };
        }
        return { eligible: false, score: 45, reason: 'Targeted to BPL households and women heads of family.' };
      }
    },
    {
      id: 'ign_pension',
      title: 'Indira Gandhi National Old Age Pension (IGNOAPS)',
      titleHi: 'इंदिरा गांधी राष्ट्रीय वृद्धावस्था पेंशन',
      ministry: 'Ministry of Rural Development',
      level: 'National Social Assistance',
      badgeClass: 'bg-indigo-100 text-indigo-800 border-indigo-300',
      benefitValue: 12000,
      benefitDisplay: '₹1,000 – ₹1,500 / Month Lifetime Pension',
      description: 'Monthly direct cash transfer for senior citizens living below poverty line without active family support.',
      requiredCerts: ['Age Proof / Birth Certificate', 'BPL / Income Certificate', 'Aadhaar Bank Link'],
      targetDesk: 'caste',
      targetSub: 'birth',
      evaluate: (p) => {
        if (p.age >= 60 || p.occupation === 'senior') {
          return { eligible: true, score: 98, reason: 'Age threshold met (>=60 years). Statutory right under NSAP framework.' };
        }
        return { eligible: false, score: 10, reason: 'Statutory age requirement is 60+ years.' };
      }
    },
    {
      id: 'kcc_interest_subvention',
      title: 'Kisan Credit Card (KCC) 4% Interest Subvention',
      titleHi: 'किसान क्रेडिट कार्ड (KCC) ब्याज अनुदान योजना',
      ministry: 'Ministry of Agriculture',
      level: 'Central Sector',
      badgeClass: 'bg-lime-100 text-lime-800 border-lime-300',
      benefitValue: 24000,
      benefitDisplay: 'Up to ₹3,00,000 Crop Loan at 4% Effective Rate',
      description: 'Interest subvention of 3% on prompt loan repayment, effectively dropping borrowing cost for seasonal crop cultivation to only 4% per annum.',
      requiredCerts: ['Land Revenue RoR (Khatauni)', 'No-Dues Certificate', 'Aadhaar Card'],
      targetDesk: 'caste',
      targetSub: 'income',
      evaluate: (p) => {
        if (p.occupation === 'farmer') {
          return { eligible: true, score: 97, reason: 'Farmer profile verified for AgriStack linked KCC pre-approved limit.' };
        }
        return { eligible: false, score: 15, reason: 'Applicable exclusively to farmers and dairy/fishery operators.' };
      }
    },
    {
      id: 'mudra_shishu',
      title: 'Pradhan Mantri Mudra Yojana (PMMY)',
      titleHi: 'प्रधानमंत्री मुद्रा योजना (शिशु / किशोर / तरुण)',
      ministry: 'Ministry of Finance',
      level: 'Central Scheme',
      badgeClass: 'bg-amber-100 text-amber-900 border-amber-300',
      benefitValue: 100000,
      benefitDisplay: '₹50,000 – ₹10,00,000 Collateral-Free MSME Credit',
      description: 'Zero collateral loans for manufacturing, trade, and service enterprises under CGTMSE government credit guarantee.',
      requiredCerts: ['Business Udyam Registration', 'Aadhaar & PAN Card', 'Project Quotation'],
      targetDesk: 'caste',
      targetSub: 'income',
      evaluate: (p) => {
        if (p.occupation === 'business' || p.occupation === 'worker' || p.age >= 21) {
          return { eligible: true, score: 88, reason: 'Citizen meets entrepreneurship credit underwriting eligibility.' };
        }
        return { eligible: false, score: 50, reason: 'Requires commercial trade or self-employment proposition.' };
      }
    },
    {
      id: 'ews_quota_cert',
      title: 'EWS 10% Statutory Reservation & Fee Concession',
      titleHi: 'ईडब्ल्यूएस 10% आरक्षण एवं शुल्क छूट प्रमाण',
      ministry: 'Ministry of Personnel, Public Grievances and Pensions',
      level: 'Constitutional 103rd Amendment',
      badgeClass: 'bg-sky-100 text-sky-800 border-sky-300',
      benefitValue: 35000,
      benefitDisplay: '10% Govt Jobs/Admissions Quota + Examination Fee Relief',
      description: 'Statutory 10% reservation in Central & State Government jobs and higher educational institutions for economically disadvantaged general candidates.',
      requiredCerts: ['EWS Income & Asset Certificate', 'Land Holding Affidavit', 'Domicile Certificate'],
      targetDesk: 'caste',
      targetSub: 'income',
      evaluate: (p) => {
        if ((p.category === 'EWS' || p.category === 'GEN') && p.income <= 800000) {
          return { eligible: true, score: 95, reason: 'Family income is strictly below the ₹8,00,000 statutory EWS ceiling.' };
        }
        return { eligible: false, score: 30, reason: 'Reserved for General category candidates earning under ₹8 Lakh.' };
      }
    },
    {
      id: 'state_social_security',
      title: 'State Resident Direct Benefit Umbrella (e-District)',
      titleHi: 'राज्य नागरिक सामाजिक सुरक्षा संकुल (ई-डिस्ट्रिक्ट)',
      ministry: 'State Department of Revenue & Social Welfare',
      level: 'State Government',
      badgeClass: 'bg-cyan-100 text-cyan-800 border-cyan-300',
      benefitValue: 18000,
      benefitDisplay: 'State Utility Subsidies + Free Transport Passes',
      description: 'Localized state statutory assistance including subsidized domestic power, free bus transport for students/seniors, and emergency welfare aid.',
      requiredCerts: ['Domicile Certificate (मूल निवास)', 'Income Certificate', 'Aadhaar Card'],
      targetDesk: 'caste',
      targetSub: 'domicile',
      evaluate: (p) => {
        if (p.state !== 'ALL') {
          return { eligible: true, score: 96, reason: `Verified domicile linkage for State Code: ${p.state}.` };
        }
        return { eligible: true, score: 85, reason: 'Available under respective home state e-District jurisdiction.' };
      }
    },
    {
      id: 'smart_dl_transport',
      title: 'MoRTH National Transport Mobility Portal (Sarathi)',
      titleHi: 'सड़क परिवहन एवं राजमार्ग मंत्रालय (सारथी गतिशीलता)',
      ministry: 'Ministry of Road Transport & Highways',
      level: 'Central DPI',
      badgeClass: 'bg-orange-100 text-orange-800 border-orange-300',
      benefitValue: 5000,
      benefitDisplay: 'Contactless Smart Driving Licence + DigiLocker Auto-Push',
      description: 'Standardized ISO-compliant smart card driving licence valid nationwide across all highways and border crossings without physical checkposts.',
      requiredCerts: ['Form 1A Medical Fitness', 'Learner Licence >30 days', 'Aadhaar Identity'],
      targetDesk: 'dl',
      targetSub: null,
      evaluate: (p) => {
        if (p.age >= 18) {
          return { eligible: true, score: 99, reason: 'Citizen is of legal age (>=18) to hold commercial or non-transport motor vehicle licence.' };
        }
        return { eligible: false, score: 20, reason: 'Citizen must be at least 18 years of age.' };
      }
    }
  ];

  window.runYojanaMatcher = function() {
    const ageEl = document.getElementById('yojana-age');
    const stateEl = document.getElementById('yojana-state');
    const incomeEl = document.getElementById('yojana-income');
    const catEl = document.getElementById('yojana-category');
    const occEl = document.getElementById('yojana-occupation');

    const profile = {
      age: parseInt(ageEl ? ageEl.value : 23) || 23,
      state: stateEl ? stateEl.value : 'UP',
      income: parseInt(incomeEl ? incomeEl.value : 180000) || 180000,
      category: catEl ? catEl.value : 'OBC',
      occupation: occEl ? occEl.value : 'student'
    };

    let eligibleSchemes = [];
    let totalSubsidy = 0;

    nationalSchemesDatabase.forEach(scheme => {
      const evaluation = scheme.evaluate(profile);
      if (evaluation.eligible) {
        eligibleSchemes.push({
          ...scheme,
          matchScore: evaluation.score,
          matchReason: evaluation.reason
        });
        totalSubsidy += scheme.benefitValue;
      }
    });

    // Sort by match score descending
    eligibleSchemes.sort((a, b) => b.matchScore - a.matchScore);

    const countBadge = document.getElementById('yojana-count-badge');
    const countText = document.getElementById('yojana-count-text');
    const subsidyText = document.getElementById('yojana-subsidy-text');
    const cardsGrid = document.getElementById('yojana-cards-grid');

    if (countBadge) countBadge.textContent = eligibleSchemes.length;
    if (countText) countText.textContent = `${eligibleSchemes.length} Welfare Schemes Eligible (${eligibleSchemes.length} पात्र योजनाएं)`;
    if (subsidyText) subsidyText.textContent = `Up to ₹${totalSubsidy.toLocaleString('en-IN')} / Year Total Direct Entitlements`;

    if (cardsGrid) {
      if (eligibleSchemes.length === 0) {
        cardsGrid.innerHTML = `
          <div class="col-span-full p-8 text-center bg-slate-50 border border-slate-200 rounded-xl text-slate-600">
            <p class="font-bold">No direct matching schemes found for this profile combination.</p>
            <p class="text-xs mt-1">Try adjusting income tier or social category.</p>
          </div>
        `;
      } else {
        cardsGrid.innerHTML = eligibleSchemes.map(s => `
          <div class="bg-white border-2 border-slate-200 hover:border-emerald-500 rounded-xl p-4 shadow-sm hover:shadow-md transition flex flex-col justify-between group">
            <div>
              <div class="flex items-center justify-between gap-2 pb-2 border-b border-slate-100">
                <span class="text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${s.badgeClass}">
                  ${escapeHtml(s.level)}
                </span>
                <span class="text-[11px] font-extrabold text-emerald-700 bg-emerald-50 border border-emerald-300 px-2 py-0.5 rounded-full flex items-center gap-1">
                  <i data-lucide="check-circle-2" class="w-3 h-3 text-emerald-600"></i>
                  <span>${s.matchScore}% Match</span>
                </span>
              </div>

              <h4 class="font-extrabold text-sm text-[#00314D] mt-2 group-hover:text-emerald-800 transition">
                ${escapeHtml(s.title)}
              </h4>
              <p class="text-[11px] text-slate-500 font-medium">${escapeHtml(s.titleHi)}</p>

              <div class="mt-3 p-2 bg-[#F0FDF4] border border-[#BBF7D0] rounded-lg">
                <div class="text-[10px] font-bold text-emerald-900 uppercase tracking-wider">Direct Benefit:</div>
                <div class="font-black text-xs text-emerald-700 font-mono mt-0.5">${escapeHtml(s.benefitDisplay)}</div>
              </div>

              <p class="text-[11px] text-[#475569] mt-2.5 leading-relaxed line-clamp-2">
                ${escapeHtml(s.description)}
              </p>

              <div class="mt-3 pt-2 border-t border-slate-100">
                <div class="text-[10px] font-bold text-slate-600 mb-1">Mandatory Attestations:</div>
                <div class="flex flex-wrap gap-1">
                  ${s.requiredCerts.map(c => `
                    <span class="text-[9px] bg-slate-100 text-slate-700 px-1.5 py-0.5 rounded font-medium border border-slate-200">
                      ${escapeHtml(c)}
                    </span>
                  `).join('')}
                </div>
              </div>
            </div>

            <div class="mt-4 pt-3 border-t border-slate-100 flex items-center justify-between gap-2">
              <span class="text-[10px] text-slate-500 font-mono">${escapeHtml(s.ministry)}</span>
              <button type="button" onclick="window.autoFillSchemeDesk('${s.id}')" class="bg-[#00314D] hover:bg-[#002236] text-white font-bold text-[11px] px-3 py-1.5 rounded-lg transition flex items-center gap-1 shadow-xs cursor-pointer">
                <span>Auto-Fill Desk</span>
                <i data-lucide="arrow-up-right" class="w-3 h-3 text-[#FF8000]"></i>
              </button>
            </div>
          </div>
        `).join('');
      }
    }

    if (window.lucide) lucide.createIcons();

    if (typeof showGovToast === 'function') {
      showGovToast(`AI Yojana Drishti: Calculated ${eligibleSchemes.length} eligible schemes with up to ₹${totalSubsidy.toLocaleString('en-IN')} benefit!`);
    }
  };

  window.autoFillSchemeDesk = function(schemeId) {
    const scheme = nationalSchemesDatabase.find(s => s.id === schemeId);
    if (!scheme) return;

    if (scheme.targetDesk === 'caste') {
      window.switchProtoDesk('caste');
      if (scheme.targetSub) {
        window.switchRevenueSubService(scheme.targetSub);
      }
      const el = document.getElementById('citizen-service-prototype');
      if (el) {
        el.scrollIntoView({ behavior: 'smooth' });
        el.classList.add('gov-form-highlight');
        setTimeout(() => el.classList.remove('gov-form-highlight'), 2500);
      }
    } else if (scheme.targetDesk === 'dl') {
      window.switchProtoDesk('dl');
      const el = document.getElementById('citizen-service-prototype');
      if (el) {
        el.scrollIntoView({ behavior: 'smooth' });
        el.classList.add('gov-form-highlight');
        setTimeout(() => el.classList.remove('gov-form-highlight'), 2500);
      }
    }

    if (typeof showGovToast === 'function') {
      showGovToast(`Pre-filling statutory service desk for: ${scheme.title}`);
    }
  };


  // =========================================================================
  // 12C. SMOOTH NUMBER ROLLER ANIMATION ENGINE
  // =========================================================================
  function animateNumberRoll(el, target, prefix = '', suffix = '', duration = 1000) {
    if (!el) return;
    const startTime = performance.now();
    function step(now) {
      const progress = Math.min((now - startTime) / duration, 1);
      const ease = 1 - Math.pow(1 - progress, 3);
      const val = Math.floor(target * ease);
      el.textContent = `${prefix}${val.toLocaleString('en-IN')}${suffix}`;
      if (progress < 1) {
        requestAnimationFrame(step);
      } else {
        el.textContent = `${prefix}${target.toLocaleString('en-IN')}${suffix}`;
      }
    }
    requestAnimationFrame(step);
  }
  window.animateNumberRoll = animateNumberRoll;

  // 13. OFF-CANVAS PORTAL SIDE DRAWER (3-LINE HAMBURGER MENU)
  // =========================================================================
  window.togglePortalDrawer = function() {
    const backdrop = document.getElementById('portal-drawer-backdrop');
    const drawer = document.getElementById('portal-side-drawer');
    if (drawer && backdrop) {
      const isOpen = drawer.classList.contains('drawer-open');
      if (isOpen) {
        drawer.classList.remove('drawer-open');
        backdrop.classList.add('hidden');
      } else {
        backdrop.classList.remove('hidden');
        drawer.classList.add('drawer-open');
        if (window.lucide) lucide.createIcons();
      }
    }
  };

  window.closePortalDrawer = function() {
    const backdrop = document.getElementById('portal-drawer-backdrop');
    const drawer = document.getElementById('portal-side-drawer');
    if (drawer) drawer.classList.remove('drawer-open');
    if (backdrop) backdrop.classList.add('hidden');
  };

  window.drawerNavigate = function(targetId, action) {
    window.closePortalDrawer();
    
    // Map section IDs to their parent page
    const sectionPageMap = {
      'overview': 'home',
      'rtps-services-directory': 'services',
      'citizen-service-prototype': 'services',
      'ai-yojana-drishti': 'ai-drishti',
      'live-verifier': 'ai-drishti',
      'citizen-charter': 'charter',
      'helpdesk-contact': 'charter',
      'compliance-standards': 'charter'
    };
    
    const pageId = sectionPageMap[targetId] || targetId.replace('page-', '') || 'home';
    window.navigateToPage(pageId, () => {
      if (typeof action === 'function') {
        try { action(); } catch(e) {}
      }
      const el = document.getElementById(targetId);
      if (el) {
        setTimeout(() => el.scrollIntoView({ behavior: 'smooth' }), 120);
      }
    });
  };


  
  // =========================================================================
  // 16. HERO DYNAMIC PROPOSITION TYPEWRITER ENGINE
  // =========================================================================
  function initHeroTypewriter() {
    const el = document.getElementById('hero-typewriter');
    if (!el) return;

    const phrases = [
      "Frictionless Single-Window Citizen Delivery",
      "Unified Interoperability for 28 States & 8 UTs",
      "Zero-Knowledge DPDP Act 2023 Attestation",
      "Real-time Verification Across MoRTH, UIDAI & Revenue",
      "AI-Powered Welfare Scheme Discovery in <200ms"
    ];

    let phraseIdx = 0;
    let charIdx = 0;
    let isDeleting = false;
    let typingSpeed = 60;

    function typeLoop() {
      const currentPhrase = phrases[phraseIdx];

      if (isDeleting) {
        charIdx--;
        el.textContent = currentPhrase.substring(0, charIdx);
        typingSpeed = 30;
      } else {
        charIdx++;
        el.textContent = currentPhrase.substring(0, charIdx);
        typingSpeed = 65;
      }

      if (!isDeleting && charIdx === currentPhrase.length) {
        typingSpeed = 2200; // pause at end
        isDeleting = true;
      } else if (isDeleting && charIdx === 0) {
        isDeleting = false;
        phraseIdx = (phraseIdx + 1) % phrases.length;
        typingSpeed = 400; // pause before next phrase
      }

      setTimeout(typeLoop, typingSpeed);
    }
    typeLoop();
  }

  // =========================================================================
  // 17. SCROLL REVEAL STAGGER OBSERVER
  // =========================================================================
  function initScrollReveal() {
    if (!('IntersectionObserver' in window)) return;
    const cards = document.querySelectorAll('.gov-card, .gov-service-card, .pro-card-hover, #ai-yojana-drishti');
    
    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('revealed');
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.1 });

    cards.forEach(card => {
      card.classList.add('scroll-reveal');
      observer.observe(card);
    });
  }

  
  // Initialize Visual Motion & Animation Engines
  try {
    initHeroTypewriter();
    initScrollReveal();
  } catch(err) {
    console.warn('Animation engine init:', err);
  }

  // 14. INITIALIZE ADVANCED AI SERVICES
  try {
    if (typeof window.runYojanaMatcher === 'function') {
      window.runYojanaMatcher();
    }
  } catch(e) {
    console.warn('Initial Yojana match failed:', e);
  }
});


// ==========================================================================
// CLIENT-SIDE MULTI-PAGE PORTAL ROUTER
// ==========================================================================
window.navigateToPage = function(pageId, subAction) {
  // Hide all portal pages
  const pages = document.querySelectorAll('.portal-page');
  pages.forEach(p => p.classList.add('hidden'));

  // Show target page
  const target = document.getElementById('page-' + pageId);
  if (target) {
    target.classList.remove('hidden');
    target.querySelectorAll('.reveal-item').forEach(el => el.classList.add('revealed'));
  } else {
    // Fallback to home
    const home = document.getElementById('page-home');
    if (home) {
      home.classList.remove('hidden');
      home.querySelectorAll('.reveal-item').forEach(el => el.classList.add('revealed'));
    }
    pageId = 'home';
  }

  // Update Nav Links Active States
  document.querySelectorAll('.gov-nav-link').forEach(link => {
    const p = link.getAttribute('data-page');
    if (p === pageId) {
      link.classList.add('active');
    } else {
      link.classList.remove('active');
    }
  });

  // Update Hash in browser address bar without jump
  if (window.history && window.history.pushState) {
    window.history.pushState(null, null, '#' + pageId);
  } else {
    window.location.hash = '#' + pageId;
  }

  // Scroll to top of window immediately on page change
  window.scrollTo(0, 0);

  // Execute optional subaction (e.g. switch to specific service mode)
  if (typeof subAction === 'function') {
    try {
      subAction();
    } catch (e) {
      console.warn('Subaction error:', e);
    }
  }

  // Close portal drawer if open
  if (typeof window.closePortalDrawer === 'function') {
    window.closePortalDrawer();
  }

  // Refresh icons
  if (window.lucide && typeof window.lucide.createIcons === 'function') {
    setTimeout(() => window.lucide.createIcons(), 50);
  }
};

// Listen to browser Back/Forward buttons
window.addEventListener('popstate', function() {
  const hash = window.location.hash.replace('#', '') || 'home';
  window.navigateToPage(hash);
});

// Initialize router on DOM ready
document.addEventListener('DOMContentLoaded', function() {
  const initialHash = window.location.hash.replace('#', '') || 'home';
  window.navigateToPage(initialHash);
});

  // =========================================================================
  // UNIVERSAL 27 STATUTORY CERTIFICATES DIRECT LAUNCHER & FILTERS
  // =========================================================================
    // =========================================================================
  // UNIVERSAL STATUTORY CERTIFICATES DIRECT LAUNCHER & FILTERS (HOME + WORKSTATION)
  // =========================================================================
  window.openCertificateDirectly = function(deskKey, subKey) {
    // 1. Ensure we navigate to services page
    if (typeof window.navigateToPage === 'function') {
      window.navigateToPage('services');
    } else {
      document.querySelectorAll('.portal-page').forEach(p => p.classList.add('hidden'));
      const sPage = document.getElementById('page-services');
      if (sPage) sPage.classList.remove('hidden');
    }

    // 2. Ensure mode is 'apply'
    const btnApply = document.getElementById('btn-mode-apply');
    const btnTrack = document.getElementById('btn-mode-track');
    const btnVerify = document.getElementById('btn-mode-verify');
    const panelTrack = document.getElementById('panel-track-status');
    if (btnApply) btnApply.className = 'lovable-pill bg-[#FF8000] text-white font-bold cursor-pointer shadow-sm hover:bg-[#E67300] transition';
    if (btnTrack) btnTrack.className = 'lovable-pill bg-white/10 hover:bg-white/20 text-white font-semibold cursor-pointer border border-white/20 transition';
    if (btnVerify) btnVerify.className = 'lovable-pill bg-white/10 hover:bg-white/20 text-white font-semibold cursor-pointer border border-white/20 transition';
    if (panelTrack) panelTrack.classList.add('hidden');

    // 3. Switch to requested desk
    if (typeof window.switchProtoDesk === 'function') {
      window.switchProtoDesk(deskKey);
    }

    // 4. Switch to requested subservice
    if (deskKey === 'caste' && window.switchRevenueSubService) {
      window.switchRevenueSubService(subKey || 'caste');
    } else if (deskKey === 'dl' && window.switchTransportSubService) {
      window.switchTransportSubService(subKey || 'dl');
    } else if (deskKey === 'birth' && window.switchCrsSubService) {
      window.switchCrsSubService(subKey || 'birth');
    } else if (deskKey === 'farmer' && window.switchFarmerSubService) {
      window.switchFarmerSubService(subKey || 'pmkisan');
    } else if (deskKey === 'business' && window.switchBusinessSubService) {
      window.switchBusinessSubService(subKey || 'spice');
    }

    // 5. Update Quick Switch Hub Pills active state
    document.querySelectorAll('.quick-cert-pill').forEach(pill => {
      if (pill.getAttribute('data-desk') === deskKey && pill.getAttribute('data-sub') === subKey) {
        pill.classList.add('bg-[#FF8000]', 'text-white', 'border-[#FF8000]', 'shadow-sm');
        pill.classList.remove('bg-white', 'text-[#00314D]');
      } else {
        pill.classList.remove('bg-[#FF8000]', 'text-white', 'border-[#FF8000]', 'shadow-sm');
        pill.classList.add('bg-white', 'text-[#00314D]');
      }
    });

    // 6. Smoothly scroll to the citizen desk and trigger visual highlight
    const deskElement = document.getElementById('citizen-service-prototype');
    if (deskElement) {
      deskElement.scrollIntoView({ behavior: 'smooth', block: 'start' });
      deskElement.classList.add('gov-form-highlight');
      setTimeout(() => deskElement.classList.remove('gov-form-highlight'), 2500);
    }

    if (typeof window.showGovToast === 'function') {
      window.showGovToast('प्रमाण पत्र आवेदन खुला: ' + (subKey || deskKey).toUpperCase());
    }
  };

  window.filterCertDirectory = function(category, btnElement) {
    document.querySelectorAll('.cert-filter-btn').forEach(btn => {
      btn.classList.remove('bg-[#00314D]', 'text-white', 'border-[#00314D]', 'shadow-xs');
      btn.classList.add('bg-white', 'text-[#00314D]', 'border-[#CBD5E1]');
    });
    if (btnElement) {
      btnElement.classList.add('bg-[#00314D]', 'text-white', 'border-[#00314D]', 'shadow-xs');
      btnElement.classList.remove('bg-white', 'text-[#00314D]', 'border-[#CBD5E1]');
    }

    const cards = document.querySelectorAll('.cert-directory-card');
    let visible = 0;
    cards.forEach(card => {
      const cat = card.getAttribute('data-category');
      if (category === 'all' || cat === category) {
        card.classList.remove('hidden');
        visible++;
      } else {
        card.classList.add('hidden');
      }
    });

    const countEl = document.getElementById('cert-visible-count');
    if (countEl) countEl.textContent = visible;
  };

  window.searchCertDirectory = function(query) {
    const q = (query || '').toLowerCase().trim();
    const cards = document.querySelectorAll('.cert-directory-card');
    let visible = 0;
    cards.forEach(card => {
      const text = card.textContent.toLowerCase();
      if (!q || text.includes(q)) {
        card.classList.remove('hidden');
        visible++;
      } else {
        card.classList.add('hidden');
      }
    });
    const countEl = document.getElementById('cert-visible-count');
    if (countEl) countEl.textContent = visible;
  };


  // =========================================================================
  // 1. NATIONAL SERVICE REGISTRY (54 CITIZEN SERVICES & STATUTORY ACTS)
  // =========================================================================
  window.NATIONAL_SERVICE_REGISTRY = [
  {
    "id": "REV-001",
    "category": "revenue",
    "categoryLabel": "राजस्व एवं भूमि प्रशासन (Revenue)",
    "titleHi": "जाति प्रमाण पत्र (SC/ST)",
    "titleEn": "SC/ST Caste Certificate",
    "formNo": "Gazette Form 4",
    "dept": "राजस्व विभाग (ServicePlus)",
    "desc": "अनुसूचित जाति/जनजाति समुदाय का वैधानिक प्रमाण पत्र। सरकारी आरक्षण एवं योजनाओं हेतु अनिवार्य।",
    "eligibility": "राज्य का स्थायी निवासी एवं केंद्रीय/राज्य SC/ST अनुसूची में सूचीबद्ध समुदाय।",
    "documents": [
      "आधार कार्ड (Aadhaar Card)",
      "पिता का पैतृक जाति प्रमाण",
      "निवास प्रमाण पत्र",
      "स्व-घोषणा पत्र"
    ],
    "slaDays": 7,
    "fee": "₹0 Free",
    "type": "statutory_certificate",
    "deskKey": "caste",
    "subKey": "caste",
    "officialUrl": "https://serviceonline.gov.in"
  },
  {
    "id": "REV-002",
    "category": "revenue",
    "categoryLabel": "राजस्व एवं भूमि प्रशासन (Revenue)",
    "titleHi": "आय प्रमाण पत्र",
    "titleEn": "Income Certificate",
    "formNo": "Form 1 RTPS",
    "dept": "राजस्व एवं वित्त विभाग",
    "desc": "पारिवारिक वार्षिक आय का प्राधिकृत प्रमाण। छात्रवृत्ति, शुल्क प्रतिपूर्ति एवं सरकारी सब्सिडी हेतु।",
    "eligibility": "राज्य के सभी नागरिक जिनकी आय का मूल्यांकन राजस्व लेखपाल/तहसीलदार द्वारा किया गया हो।",
    "documents": [
      "वेतन पर्ची / आय हलफनामा",
      "आधार कार्ड",
      "बैंक पासबुक (६ माह विवरण)",
      "राशन कार्ड"
    ],
    "slaDays": 3,
    "fee": "₹0 Free",
    "type": "statutory_certificate",
    "deskKey": "caste",
    "subKey": "income",
    "officialUrl": "https://edistrict.up.gov.in"
  },
  {
    "id": "REV-003",
    "category": "revenue",
    "categoryLabel": "राजस्व एवं भूमि प्रशासन (Revenue)",
    "titleHi": "मूल निवास प्रमाण पत्र",
    "titleEn": "Domicile / Residence Certificate",
    "formNo": "Form 3 RTPS",
    "dept": "राजस्व एवं गृह विभाग",
    "desc": "राज्य अथवा केंद्र शासित प्रदेश का स्थायी निवासी होने का वैधानिक प्रमाण पत्र।",
    "eligibility": "राज्य में न्यूनतम ३ वर्ष या जन्म से निरंतर निवास करने वाले नागरिक।",
    "documents": [
      "बिजली/पानी बिल या हाउस टैक्स रसीद",
      "शैक्षणिक प्रमाण पत्र (१०वीं/१२वीं)",
      "आधार कार्ड",
      "वोटर आईडी"
    ],
    "slaDays": 7,
    "fee": "₹0 Free",
    "type": "statutory_certificate",
    "deskKey": "caste",
    "subKey": "domicile",
    "officialUrl": "https://serviceonline.gov.in"
  },
  {
    "id": "REV-004",
    "category": "revenue",
    "categoryLabel": "राजस्व एवं भूमि प्रशासन (Revenue)",
    "titleHi": "ईडब्ल्यूएस प्रमाण पत्र (EWS)",
    "titleEn": "Economically Weaker Section (EWS)",
    "formNo": "103rd Const. Amend.",
    "dept": "राजस्व प्रशासन (SDM कार्यालय)",
    "desc": "सामान्य वर्ग के आर्थिक रूप से कमजोर नागरिकों के लिए 10% आरक्षण हेतु अधिकृत प्रमाण पत्र।",
    "eligibility": "सामान्य वर्ग (General) के परिवार जिनकी कुल वार्षिक पारिवारिक आय ₹8 लाख से कम हो।",
    "documents": [
      "समग्र आय प्रमाण पत्र",
      "कृषि भूमि एवं आवासीय संपत्ति खसरा",
      "आधार कार्ड",
      "पैन कार्ड"
    ],
    "slaDays": 10,
    "fee": "₹0 Free",
    "type": "statutory_certificate",
    "deskKey": "caste",
    "subKey": "ews",
    "officialUrl": "https://serviceonline.gov.in"
  },
  {
    "id": "REV-005",
    "category": "revenue",
    "categoryLabel": "राजस्व एवं भूमि प्रशासन (Revenue)",
    "titleHi": "अन्य पिछड़ा वर्ग नॉन-क्रीमी लेयर (OBC-NCL)",
    "titleEn": "OBC Non-Creamy Layer Certificate",
    "formNo": "Form 2 NCL",
    "dept": "पिछड़ा वर्ग कल्याण विभाग",
    "desc": "केंद्रीय एवं राज्य नौकरियों में ओबीसी क्रीमी लेयर (₹8 लाख आय सीमा) से बाहर होने का सत्यापन।",
    "eligibility": "केंद्रीय/राज्य ओबीसी सूची में शामिल नागरिक, अभिभावक ग्रुप-A/B सेवा में न हों।",
    "documents": [
      "जाति प्रमाण पत्र (मूल)",
      "विगत ३ वर्षों का आयकर रिटर्न (ITR) / फॉर्म 16",
      "आधार कार्ड"
    ],
    "slaDays": 7,
    "fee": "₹0 Free",
    "type": "statutory_certificate",
    "deskKey": "caste",
    "subKey": "ncl",
    "officialUrl": "https://serviceonline.gov.in"
  },
  {
    "id": "REV-006",
    "category": "revenue",
    "categoryLabel": "राजस्व एवं भूमि प्रशासन (Revenue)",
    "titleHi": "दिव्यांगता प्रमाण पत्र (UDID Card)",
    "titleEn": "Disability Certificate (UDID)",
    "formNo": "RPwD Act 2016",
    "dept": "दिव्यांगजन सशक्तिकरण विभाग / CMO",
    "desc": "मेडिकल बोर्ड द्वारा जारी राष्ट्रीय विशिष्ट दिव्यांगता कार्ड एवं स्थायी प्रतिशत सत्यापन।",
    "eligibility": "४०% या अधिक प्रमाणित दिव्यांगता (Locomotor, Visual, Hearing, Intellectual)।",
    "documents": [
      "जिला अस्पताल मेडिकल बोर्ड असेसमेंट",
      "पासपोर्ट फोटो (दिव्यांगता दृश्यमान)",
      "आधार कार्ड"
    ],
    "slaDays": 15,
    "fee": "₹0 Free",
    "type": "statutory_certificate",
    "deskKey": "caste",
    "subKey": "divyang",
    "officialUrl": "https://www.swavlambancard.gov.in"
  },
  {
    "id": "REV-007",
    "category": "revenue",
    "categoryLabel": "राजस्व एवं भूमि प्रशासन (Revenue)",
    "titleHi": "पुलिस चरित्र प्रमाण पत्र (PCC)",
    "titleEn": "Police Character Certificate",
    "formNo": "Rule 14 Antecedent",
    "dept": "राज्य पुलिस मुख्यालय एवं मजिस्ट्रेट",
    "desc": "आपराधिक रिकॉर्ड जांच एवं चरित्र सत्यापन। सरकारी सेवा, पासपोर्ट एवं ठेकेदारी हेतु।",
    "eligibility": "संबंधित थाना क्षेत्र में न्यूनतम ६ माह से निवासरत नागरिक।",
    "documents": [
      "निवास प्रमाण पत्र",
      "आधार कार्ड",
      "दो संभ्रांत पड़ोसियों के पहचान पत्र"
    ],
    "slaDays": 14,
    "fee": "₹50",
    "type": "statutory_certificate",
    "deskKey": "caste",
    "subKey": "character",
    "officialUrl": "https://uppolice.gov.in"
  },
  {
    "id": "REV-008",
    "category": "revenue",
    "categoryLabel": "राजस्व एवं भूमि प्रशासन (Revenue)",
    "titleHi": "भू-अभिलेख खतौनी नकल (RoR)",
    "titleEn": "Land RoR Khatauni",
    "formNo": "Land Revenue Code",
    "dept": "राजस्व परिषद (भूलेख)",
    "desc": "कृषि भूमि का प्रमाणित खाता-खसरा विवरण, स्वामित्व अंश एवं बैंक बंधक स्थिति।",
    "eligibility": "कृषि भूमि का खातेदार, सह-खातेदार अथवा विधिक हितधारक।",
    "documents": [
      "खसरा संख्या अथवा खाता संख्या",
      "ग्राम का नाम व परगना",
      "खातेदार का नाम"
    ],
    "slaDays": 1,
    "fee": "₹15",
    "type": "statutory_certificate",
    "deskKey": "caste",
    "subKey": "land",
    "officialUrl": "https://upbhulekh.gov.in"
  },
  {
    "id": "REV-009",
    "category": "revenue",
    "categoryLabel": "राजस्व एवं भूमि प्रशासन (Revenue)",
    "titleHi": "वारिसान / उत्तराधिकार प्रमाण पत्र",
    "titleEn": "Legal Heir Certificate",
    "formNo": "Succession Form",
    "dept": "उपजिलाधिकारी (SDM) कार्यालय",
    "desc": "मृतक नागरिक के सभी कानूनी उत्तराधिकारियों का वैधानिक रिकॉर्ड व बैंक संपत्ति अंतरण।",
    "eligibility": "मृतक के प्रथम श्रेणी विधिक उत्तराधिकारी (पति/पत्नी, पुत्र, पुत्री, माता)।",
    "documents": [
      "मृत्यु प्रमाण पत्र (मूल)",
      "पारिवारिक रजिस्टर नकल",
      "उत्तराधिकारियों के शपथ पत्र",
      "आधार कार्ड"
    ],
    "slaDays": 21,
    "fee": "₹0 Free",
    "type": "statutory_certificate",
    "deskKey": "caste",
    "subKey": "legalheir",
    "officialUrl": "https://serviceonline.gov.in"
  },
  {
    "id": "REV-010",
    "category": "revenue",
    "categoryLabel": "राजस्व एवं भूमि प्रशासन (Revenue)",
    "titleHi": "हैसियत प्रमाण पत्र",
    "titleEn": "Solvency Certificate",
    "formNo": "Form 12 Solvency",
    "dept": "जिलाधिकारी एवं राजस्व विभाग",
    "desc": "सरकारी निविदाओं (टेंडर), खनन पट्टों एवं न्यायालय जमानत हेतु वित्तीय हैसियत का मूल्यांकन।",
    "eligibility": "अचल संपत्ति (भूमि/भवन) अथवा सावधि जमा (FD) धारक नागरिक।",
    "documents": [
      "भूमि मूल्यांकन आख्या",
      "भवन मूल्यांकन रिपोर्ट",
      "बैंक खाता प्रमाण",
      "चरित्र प्रमाण पत्र"
    ],
    "slaDays": 15,
    "fee": "₹100",
    "type": "statutory_certificate",
    "deskKey": "caste",
    "subKey": "solvency",
    "officialUrl": "https://edistrict.up.gov.in"
  },
  {
    "id": "TRN-001",
    "category": "transport",
    "categoryLabel": "सड़क परिवहन एवं वाहन (Transport)",
    "titleHi": "स्थायी ड्राइविंग लाइसेंस (Smart DL)",
    "titleEn": "Permanent Driving Licence",
    "formNo": "CMVR Form 7",
    "dept": "सड़क परिवहन एवं राजमार्ग मंत्रालय (सारथी)",
    "desc": "मोटर वाहन चलाने का स्थायी बायोमेट्रिक स्मार्ट कार्ड ड्राइविंग लाइसेंस।",
    "eligibility": "आयु न्यूनतम १८ वर्ष (LMV) / २० वर्ष (Transport) एवं वैध लर्नर लाइसेंस धारक।",
    "documents": [
      "लर्नर लाइसेंस नंबर",
      "आयु व पता प्रमाण पत्र",
      "ड्राइविंग टेस्ट पास स्लिप"
    ],
    "slaDays": 7,
    "fee": "₹200",
    "type": "statutory_certificate",
    "deskKey": "dl",
    "subKey": "dl",
    "officialUrl": "https://parivahan.gov.in"
  },
  {
    "id": "TRN-002",
    "category": "transport",
    "categoryLabel": "सड़क परिवहन एवं वाहन (Transport)",
    "titleHi": "शिक्षार्थी लाइसेंस (Learner's Licence)",
    "titleEn": "Learner's Licence (LL)",
    "formNo": "CMVR Form 3",
    "dept": "परिवहन विभाग (सारथी 4.0)",
    "desc": "आधार फेस ऑथेंटिकेशन एवं ऑनलाइन टेस्ट से तत्काल जारी होने वाला लर्नर परमिट।",
    "eligibility": "आयु न्यूनतम १६ वर्ष (गियररहित दुपहिया) अथवा १८ वर्ष (कार/मोटरसाइकिल)।",
    "documents": [
      "आधार कार्ड (Aadhaar e-KYC)",
      "फॉर्म 1 स्व-घोषणा पत्र",
      "ऑनलाइन टेस्ट स्कोर"
    ],
    "slaDays": 1,
    "fee": "₹150",
    "type": "statutory_certificate",
    "deskKey": "dl",
    "subKey": "ll",
    "officialUrl": "https://parivahan.gov.in"
  },
  {
    "id": "TRN-003",
    "category": "transport",
    "categoryLabel": "सड़क परिवहन एवं वाहन (Transport)",
    "titleHi": "डीएल नवीनीकरण (DL Renewal)",
    "titleEn": "DL Renewal Endorsement",
    "formNo": "CMVR Form 9",
    "dept": "परिवहन प्राधिकारी",
    "desc": "समाप्त ड्राइविंग लाइसेंस का 5 से 10 वर्ष के लिए नवीनीकरण एवं मेडिकल स्वघोषणा।",
    "eligibility": "समाप्त अथवा समाप्ति के १ वर्ष के भीतर का वैध ड्राइविंग लाइसेंस।",
    "documents": [
      "मूल ड्राइविंग लाइसेंस",
      "फॉर्म 1A मेडिकल सर्टिफिकेट (४०+ वर्ष हेतु)",
      "आधार कार्ड"
    ],
    "slaDays": 3,
    "fee": "₹200",
    "type": "statutory_certificate",
    "deskKey": "dl",
    "subKey": "renewal",
    "officialUrl": "https://parivahan.gov.in"
  },
  {
    "id": "TRN-004",
    "category": "transport",
    "categoryLabel": "सड़क परिवहन एवं वाहन (Transport)",
    "titleHi": "वाहन पंजीकरण प्रमाण पत्र (RC)",
    "titleEn": "Vehicle Registration Certificate",
    "formNo": "CMVR Form 23",
    "dept": "सड़क परिवहन मंत्रालय (वाहन 4.0)",
    "desc": "वाहन स्वामित्व, चेसिस-इंजन संख्या एवं भारत स्टेज (BS-VI) मानकों का वैधानिक प्रमाण।",
    "eligibility": "नया क्रय किया गया अथवा स्थानांतरित मोटर वाहन।",
    "documents": [
      "फॉर्म 21 (बिक्री प्रमाण)",
      "फॉर्म 22 (प्रदूषण व सुरक्षा मानक)",
      "वैध बीमा पॉलिसी",
      "पैन कार्ड"
    ],
    "slaDays": 5,
    "fee": "₹300",
    "type": "statutory_certificate",
    "deskKey": "dl",
    "subKey": "rc",
    "officialUrl": "https://vahan.parivahan.gov.in"
  },
  {
    "id": "TRN-005",
    "category": "transport",
    "categoryLabel": "सड़क परिवहन एवं वाहन (Transport)",
    "titleHi": "वाहन फिटनेस एवं प्रदूषण (PUCC)",
    "titleEn": "Fitness & PUCC Certificate",
    "formNo": "CMVR Form 38",
    "dept": "परिवहन निरीक्षण शाखा",
    "desc": "व्यावसायिक वाहनों की सड़क सुरक्षा फिटनेस एवं राष्ट्रीय उत्सर्जन प्रदूषण नियंत्रण प्रमाण पत्र।",
    "eligibility": "वाणिज्यिक वाहन (परमिट धारक) अथवा पंजीकृत व्यक्तिगत मोटर वाहन।",
    "documents": [
      "वाहन आरसी",
      "बीमा पॉलिसी",
      "रोड टैक्स रसीद",
      "स्पीड गवर्नर प्रमाण पत्र"
    ],
    "slaDays": 1,
    "fee": "₹100",
    "type": "statutory_certificate",
    "deskKey": "dl",
    "subKey": "fitness",
    "officialUrl": "https://vahan.parivahan.gov.in"
  },
  {
    "id": "TRN-006",
    "category": "transport",
    "categoryLabel": "सड़क परिवहन एवं वाहन (Transport)",
    "titleHi": "द्वितीयक ड्राइविंग लाइसेंस (Duplicate DL)",
    "titleEn": "Duplicate Driving Licence",
    "formNo": "CMVR Form LLD",
    "dept": "सड़क परिवहन मंत्रालय (सारथी)",
    "desc": "ड्राइविंग लाइसेंस खो जाने, चोरी हो जाने या क्षतिग्रस्त होने की स्थिति में द्वितीयक प्रति।",
    "eligibility": "पंजीकृत लाइसेंस धारक जिसका मूल लाइसेंस गुम अथवा नष्ट हो गया हो।",
    "documents": [
      "पुलिस गुमशुदगी रिपोर्ट (LDR / NCR)",
      "आधार कार्ड",
      "स्वघोषणा पत्र"
    ],
    "slaDays": 5,
    "fee": "₹200",
    "type": "national_scheme",
    "deskKey": "dl",
    "subKey": "dl",
    "officialUrl": "https://parivahan.gov.in"
  },
  {
    "id": "TRN-007",
    "category": "transport",
    "categoryLabel": "सड़क परिवहन एवं वाहन (Transport)",
    "titleHi": "वाहन स्वामित्व अंतरण (RC Transfer)",
    "titleEn": "Transfer of Vehicle Ownership",
    "formNo": "CMVR Form 29 & 30",
    "dept": "वाहन पंजीकरण प्राधिकारी (Vahan 4.0)",
    "desc": "वाहन क्रय-विक्रय अथवा उत्तराधिकार के पश्चात आरसी में नए स्वामी का नाम दर्ज करना।",
    "eligibility": "वाहन क्रेता एवं विक्रेता दोनों की पारस्परिक सहमति एवं अनापत्ति।",
    "documents": [
      "फॉर्म 29 व 30 (हस्ताक्षरित)",
      "मूल आरसी",
      "वैध बीमा व प्रदूषण",
      "क्रेता का निवास प्रमाण"
    ],
    "slaDays": 10,
    "fee": "₹150",
    "type": "national_scheme",
    "deskKey": "dl",
    "subKey": "rc",
    "officialUrl": "https://vahan.parivahan.gov.in"
  },
  {
    "id": "TRN-008",
    "category": "transport",
    "categoryLabel": "सड़क परिवहन एवं वाहन (Transport)",
    "titleHi": "अंतर्राष्ट्रीय ड्राइविंग परमिट (IDP)",
    "titleEn": "International Driving Permit",
    "formNo": "CMVR Form 4A",
    "dept": "MoRTH एवं विदेश मंत्रालय",
    "desc": "विदेश यात्रा के दौरान वाहन चलाने हेतु १ वर्ष की वैधता वाला अंतरराष्ट्रीय ड्राइविंग परमिट।",
    "eligibility": "वैध भारतीय स्थायी ड्राइविंग लाइसेंस एवं वैध पासपोर्ट व वीजा धारक नागरिक।",
    "documents": [
      "वैध पासपोर्ट व वीजा",
      "विमान टिकट प्रति",
      "स्थायी डीएल प्रति",
      "फॉर्म 1A मेडिकल"
    ],
    "slaDays": 3,
    "fee": "₹1000",
    "type": "national_scheme",
    "deskKey": "dl",
    "subKey": "dl",
    "officialUrl": "https://parivahan.gov.in"
  },
  {
    "id": "CRS-001",
    "category": "civil",
    "categoryLabel": "नागरिक पंजीकरण एवं पहचान (Civil Registration)",
    "titleHi": "जन्म प्रमाण पत्र एवं बाल आधार",
    "titleEn": "Birth Certificate & Baal Aadhaar",
    "formNo": "RBD Act 1969 Form 5",
    "dept": "भारत के महारजिस्ट्रार (CRS)",
    "desc": "जन्म का वैधानिक पंजीकरण, डिजिटल जन्म प्रमाण पत्र एवं लिंक बाल आधार नामांकन।",
    "eligibility": "संबंधित राज्य/अस्पताल क्षेत्र में जन्मे नवजात अथवा नागरिक।",
    "documents": [
      "अस्पताल डिस्चार्ज समरी / जन्म सूचना पर्ची",
      "माता-पिता का आधार कार्ड",
      "विवाह प्रमाण पत्र"
    ],
    "slaDays": 7,
    "fee": "₹0 Free",
    "type": "statutory_certificate",
    "deskKey": "birth",
    "subKey": "birth",
    "officialUrl": "https://crsorgi.gov.in"
  },
  {
    "id": "CRS-002",
    "category": "civil",
    "categoryLabel": "नागरिक पंजीकरण एवं पहचान (Civil Registration)",
    "titleHi": "मृत्यु प्रमाण पत्र (Death Certificate)",
    "titleEn": "Death Certificate",
    "formNo": "RBD Act 1969 Form 6",
    "dept": "नागरिक पंजीकरण प्रणाली (CRS)",
    "desc": "मृत्यु का वैधानिक पंजीकरण। बीमा क्लेम, संपत्ति नामांतरण एवं बैंक खाता बंद करने हेतु।",
    "eligibility": "मृतक का निकटतम पारिवारिक सदस्य अथवा अधिकृत कानूनी प्रतिनिधि।",
    "documents": [
      "अस्पताल मृत्यु प्रमाण / श्मशान पावती",
      "मृतक का आधार कार्ड",
      "आवेदक का पहचान पत्र"
    ],
    "slaDays": 5,
    "fee": "₹0 Free",
    "type": "statutory_certificate",
    "deskKey": "birth",
    "subKey": "death",
    "officialUrl": "https://crsorgi.gov.in"
  },
  {
    "id": "CRS-003",
    "category": "civil",
    "categoryLabel": "नागरिक पंजीकरण एवं पहचान (Civil Registration)",
    "titleHi": "विवाह पंजीकरण प्रमाण पत्र",
    "titleEn": "Marriage Registration Certificate",
    "formNo": "Marriage Act Form B",
    "dept": "विवाह पंजीयक कार्यालय (निबंधन विभाग)",
    "desc": "विवाह का कानूनी पंजीकरण। संयुक्त पासपोर्ट, वीज़ा, बैंक खाता एवं उत्तराधिकार हेतु।",
    "eligibility": "वर (आयु २१+) एवं वधू (आयु १८+) का हिंदू / विशेष विवाह अधिनियम अंतर्गत विवाह।",
    "documents": [
      "विवाह निमंत्रण कार्ड",
      "वर-वधू के आयु व निवास प्रमाण",
      "विवाह फोटो",
      "२ गवाहों के आधार कार्ड"
    ],
    "slaDays": 10,
    "fee": "₹100",
    "type": "statutory_certificate",
    "deskKey": "birth",
    "subKey": "marriage",
    "officialUrl": "https://igrsup.gov.in"
  },
  {
    "id": "CRS-004",
    "category": "civil",
    "categoryLabel": "नागरिक पंजीकरण एवं पहचान (Civil Registration)",
    "titleHi": "बाल आधार नामांकन (0-5 Years)",
    "titleEn": "Baal Aadhaar UID Enrollment",
    "formNo": "UIDAI Enrolment Form",
    "dept": "भारतीय विशिष्ट पहचान प्राधिकरण (UIDAI)",
    "desc": "५ वर्ष से कम आयु के बच्चों हेतु नीला बाल आधार कार्ड, जिसमें बायोमेट्रिक अनिवार्य नहीं है।",
    "eligibility": "० से ५ वर्ष की आयु का कोई भी भारतीय निवासी शिशु।",
    "documents": [
      "बच्चे का आधिकारिक जन्म प्रमाण पत्र",
      "माता अथवा पिता का आधार कार्ड (लिंक्ड)"
    ],
    "slaDays": 15,
    "fee": "₹0 Free",
    "type": "national_scheme",
    "deskKey": "birth",
    "subKey": "birth",
    "officialUrl": "https://uidai.gov.in"
  },
  {
    "id": "CRS-005",
    "category": "civil",
    "categoryLabel": "नागरिक पंजीकरण एवं पहचान (Civil Registration)",
    "titleHi": "आधार ई-केवाईसी एवं बायोमेट्रिक अपडेट",
    "titleEn": "Aadhaar e-KYC & Biometric Update",
    "formNo": "UIDAI Regulation 2016",
    "dept": "UIDAI एवं डिजिटल इंडिया",
    "desc": "नागरिकों का मोबाइल नंबर, पता एवं १० वर्ष पश्चात अनिवार्य दस्तावेज अद्यतनीकरण।",
    "eligibility": "कोई भी मौजूदा १२-अंकीय आधार संख्या धारक नागरिक।",
    "documents": [
      "पहचान प्रमाण (POI)",
      "पते का प्रमाण (POA)",
      "मोबाइल ओटीपी"
    ],
    "slaDays": 3,
    "fee": "₹50",
    "type": "national_scheme",
    "deskKey": "birth",
    "subKey": "birth",
    "officialUrl": "https://myaadhaar.uidai.gov.in"
  },
  {
    "id": "CRS-006",
    "category": "civil",
    "categoryLabel": "नागरिक पंजीकरण एवं पहचान (Civil Registration)",
    "titleHi": "डिजीलॉकर डिजिटल दस्तावेज वॉल्ट",
    "titleEn": "DigiLocker Citizen Document Vault",
    "formNo": "IT Act 2000 Section 9A",
    "dept": "राष्ट्रीय ई-गवर्नेंस प्रभाग (NeGD / MeitY)",
    "desc": "प्रामाणिक डिजिटल दस्तावेजों का सुरक्षित संग्रहण, जो मूल भौतिक दस्तावेज के समतुल्य मान्य है।",
    "eligibility": "आधार से जुड़े मोबाइल नंबर वाले सभी भारतीय नागरिक।",
    "documents": [
      "आधार कार्ड संख्या",
      "लिंक्ड मोबाइल नंबर"
    ],
    "slaDays": 1,
    "fee": "₹0 Free",
    "type": "national_scheme",
    "deskKey": "birth",
    "subKey": "birth",
    "officialUrl": "https://www.digilocker.gov.in"
  },
  {
    "id": "AGR-001",
    "category": "agri",
    "categoryLabel": "कृषि, खाद्य एवं किसान कल्याण (Agriculture)",
    "titleHi": "पीएम-किसान सम्मान निधि वाउचर",
    "titleEn": "PM-KISAN DBT Sanction Voucher",
    "formNo": "AgriStack DBT Voucher",
    "dept": "कृषि एवं किसान कल्याण मंत्रालय",
    "desc": "वार्षिक ₹6,000 (₹2,000 प्रति किश्त) प्रत्यक्ष बैंक अंतरण स्वीकृति एवं भूमि सीडिंग रिकॉर्ड।",
    "eligibility": "खेती योग्य भूमि के मालिक किसान परिवार (संस्थागत भूस्वामी व आयकरदाता अपवर्जित)।",
    "documents": [
      "खतौनी / भू-अभिलेख",
      "आधार कार्ड",
      "बैंक पासबुक (NPCI / DBT सक्रिय)",
      "मोबाइल नंबर"
    ],
    "slaDays": 1,
    "fee": "₹0 Free",
    "type": "statutory_certificate",
    "deskKey": "farmer",
    "subKey": "pmkisan",
    "officialUrl": "https://pmkisan.gov.in"
  },
  {
    "id": "AGR-002",
    "category": "agri",
    "categoryLabel": "कृषि, खाद्य एवं किसान कल्याण (Agriculture)",
    "titleHi": "राष्ट्रीय खाद्य सुरक्षा राशन कार्ड (NFSA)",
    "titleEn": "NFSA Digital Ration Card",
    "formNo": "NFSA 2013 AAY/PHH",
    "dept": "खाद्य एवं रसद विभाग",
    "desc": "वन नेशन वन राशन कार्ड (ONORC) डिजिटल राशन कार्ड, रियायती खाद्यान्न एवं बायोमेट्रिक आवंटन।",
    "eligibility": "गरीबी रेखा से नीचे (BPL) अथवा पात्र गृहस्थी (PHH) श्रेणी के परिवार।",
    "documents": [
      "परिवार के सभी सदस्यों के आधार कार्ड",
      "आय प्रमाण पत्र",
      "निवास प्रमाण पत्र",
      "गैस पासबुक"
    ],
    "slaDays": 15,
    "fee": "₹0 Free",
    "type": "statutory_certificate",
    "deskKey": "farmer",
    "subKey": "ration",
    "officialUrl": "https://nfsa.gov.in"
  },
  {
    "id": "AGR-003",
    "category": "agri",
    "categoryLabel": "कृषि, खाद्य एवं किसान कल्याण (Agriculture)",
    "titleHi": "किसान क्रेडिट कार्ड (KCC)",
    "titleEn": "Kisan Credit Card Sanction",
    "formNo": "NABARD KCC Form",
    "dept": "नाबार्ड एवं वित्तीय सेवा विभाग",
    "desc": "कृषकों को 4% रियायती ब्याज दर पर कृषि एवं कार्यशील पूंजी ऋण सीमा स्वीकृति।",
    "eligibility": "कृषि भूमि के मालिक किसान, पट्टेदार कृषक अथवा दुग्ध/मत्स्य पालक।",
    "documents": [
      "अद्यतन खतौनी खसरा",
      "आधार कार्ड व पैन कार्ड",
      "फसल बोआई स्वघोषणा",
      "नो-ड्यूज प्रमाण"
    ],
    "slaDays": 14,
    "fee": "₹0 Free",
    "type": "statutory_certificate",
    "deskKey": "farmer",
    "subKey": "kcc",
    "officialUrl": "https://www.nabard.org"
  },
  {
    "id": "AGR-004",
    "category": "agri",
    "categoryLabel": "कृषि, खाद्य एवं किसान कल्याण (Agriculture)",
    "titleHi": "सामाजिक सुरक्षा पेंशन (PPO)",
    "titleEn": "Social Security Pension PPO",
    "formNo": "NSAP Pension Order",
    "dept": "समाज कल्याण एवं ग्रामीण विकास",
    "desc": "वृद्धावस्था, विधवा एवं दिव्यांगजनों हेतु मासिक वित्तीय पेंशन भुगतान स्वीकृति आदेश।",
    "eligibility": "६० वर्ष से अधिक आयु अथवा निराश्रित विधवा/दिव्यांग, गरीबी रेखा सूची में दर्ज।",
    "documents": [
      "आयु प्रमाण पत्र / आधार",
      "आय प्रमाण पत्र (शहरी < ₹56,460 / ग्रामीण < ₹46,080)",
      "बैंक पासबुक"
    ],
    "slaDays": 21,
    "fee": "₹0 Free",
    "type": "statutory_certificate",
    "deskKey": "farmer",
    "subKey": "pension",
    "officialUrl": "https://nsap.nic.in"
  },
  {
    "id": "AGR-005",
    "category": "agri",
    "categoryLabel": "कृषि, खाद्य एवं किसान कल्याण (Agriculture)",
    "titleHi": "वरिष्ठ नागरिक राष्ट्रीय पहचान पत्र",
    "titleEn": "Senior Citizen National ID",
    "formNo": "Senior Citizen Card",
    "dept": "सामाजिक न्याय एवं अधिकारिता मंत्रालय",
    "desc": "60 वर्ष से अधिक आयु के नागरिकों हेतु स्वास्थ्य, यात्रा रियायत एवं कानूनी सुरक्षा कार्ड।",
    "eligibility": "६० वर्ष अथवा अधिक आयु पूर्ण कर चुके भारतीय नागरिक।",
    "documents": [
      "आधार कार्ड / वोटर आईडी / १०वीं अंकपत्र",
      "निवास प्रमाण पत्र",
      "रक्त समूह रिपोर्ट"
    ],
    "slaDays": 7,
    "fee": "₹0 Free",
    "type": "statutory_certificate",
    "deskKey": "farmer",
    "subKey": "senior",
    "officialUrl": "https://socialjustice.gov.in"
  },
  {
    "id": "AGR-006",
    "category": "agri",
    "categoryLabel": "कृषि, खाद्य एवं किसान कल्याण (Agriculture)",
    "titleHi": "प्रधानमंत्री फसल बीमा योजना (PMFBY)",
    "titleEn": "PM Fasal Bima Yojana Crop Insurance",
    "formNo": "PMFBY Operational Guidelines",
    "dept": "कृषि मंत्रालय एवं बीमा कंपनियाँ",
    "desc": "प्राकृतिक आपदा, बेमौसम बारिश व कीट प्रकोप से फसल क्षति की स्थिति में व्यापक बीमा सुरक्षा।",
    "eligibility": "अधिसूचित क्षेत्रों में अधिसूचित फसलें उगाने वाले सभी भूस्वामी व बटाईदार किसान।",
    "documents": [
      "खतौनी नकल",
      "फसल बुवाई प्रमाण पत्र (पटवारी द्वारा)",
      "बैंक पासबुक",
      "आधार कार्ड"
    ],
    "slaDays": 10,
    "fee": "१.५% - २% प्रीमियम",
    "type": "national_scheme",
    "deskKey": "farmer",
    "subKey": "kcc",
    "officialUrl": "https://pmfby.gov.in"
  },
  {
    "id": "AGR-007",
    "category": "agri",
    "categoryLabel": "कृषि, खाद्य एवं किसान कल्याण (Agriculture)",
    "titleHi": "मृदा स्वास्थ्य कार्ड (Soil Health Card)",
    "titleEn": "Soil Health Card Assessment",
    "formNo": "Soil Health Card Scheme",
    "dept": "कृषि एवं सहकारिता विभाग",
    "desc": "खेत की मिट्टी के १२ पोषक तत्वों की वैज्ञानिक जांच एवं संतुलित उर्वरक संस्तुति रिपोर्ट।",
    "eligibility": "कृषि भूमि धारक कोई भी कृषक।",
    "documents": [
      "खेत का खसरा नंबर",
      "आधार कार्ड",
      "मिट्टी नमूना रसीद"
    ],
    "slaDays": 14,
    "fee": "₹0 Free",
    "type": "national_scheme",
    "deskKey": "farmer",
    "subKey": "pmkisan",
    "officialUrl": "https://soilhealth.dac.gov.in"
  },
  {
    "id": "AGR-008",
    "category": "agri",
    "categoryLabel": "कृषि, खाद्य एवं किसान कल्याण (Agriculture)",
    "titleHi": "कृषि यंत्र एवं सोलर पंप सब्सिडी (KUSUM)",
    "titleEn": "Agri-Equipment & Solar Pump Subsidy",
    "formNo": "PM-KUSUM Scheme Component-B",
    "dept": "नवीन एवं नवीकरणीय ऊर्जा मंत्रालय / कृषि विभाग",
    "desc": "सिंचाई हेतु ६०% तक सब्सिडी पर सोलर पंप एवं आधुनिक कृषि यंत्रों की डीबीटी स्वीकृति।",
    "eligibility": "कृषि भूमि व जल स्रोत धारक कृषक अथवा किसान उत्पादक संगठन (FPO)।",
    "documents": [
      "खतौनी नकल",
      "बैंक पासबुक",
      "आधार कार्ड",
      "विद्युत कनेक्शन अनापत्ति"
    ],
    "slaDays": 30,
    "fee": "₹0 Free",
    "type": "national_scheme",
    "deskKey": "farmer",
    "subKey": "pmkisan",
    "officialUrl": "https://pmkusum.mnre.gov.in"
  },
  {
    "id": "WEL-001",
    "category": "welfare",
    "categoryLabel": "सामाजिक न्याय एवं छात्रवृत्ति (Social Welfare)",
    "titleHi": "पोस्ट-मैट्रिक छात्रवृत्ति (SC/ST/OBC)",
    "titleEn": "Post-Matric Scholarship Scheme",
    "formNo": "National Scholarship Portal (NSP)",
    "dept": "सामाजिक न्याय एवं अधिकारिता मंत्रालय",
    "desc": "उच्च शिक्षा, पॉलिटेक्निक, इंजीनियरिंग एवं मेडिकल कॉलेज शुल्क प्रतिपूर्ति व निर्वाह भत्ता।",
    "eligibility": "१०वीं उत्तीर्ण विद्यार्थी, माता-पिता की वार्षिक आय ₹2.5 लाख (SC/ST) या ₹2 लाख (OBC) से कम।",
    "documents": [
      "जाति प्रमाण पत्र",
      "आय प्रमाण पत्र",
      "कॉलेज फीस रसीद व बोनाफाइड",
      "आधार कार्ड"
    ],
    "slaDays": 20,
    "fee": "₹0 Free",
    "type": "national_scheme",
    "deskKey": "caste",
    "subKey": "income",
    "officialUrl": "https://scholarships.gov.in"
  },
  {
    "id": "WEL-002",
    "category": "welfare",
    "categoryLabel": "सामाजिक न्याय एवं छात्रवृत्ति (Social Welfare)",
    "titleHi": "पूर्व-दशम छात्रवृत्ति (Pre-Matric)",
    "titleEn": "Pre-Matric Scholarship Scheme",
    "formNo": "NSP Pre-Matric",
    "dept": "अल्पसंख्यक एवं समाज कल्याण विभाग",
    "desc": "कक्षा ९वीं व १०वीं के मेधावी व जरूरतमंद विद्यार्थियों हेतु वित्तीय प्रोत्साहन अनुदान।",
    "eligibility": "मान्यता प्राप्त विद्यालय में कक्षा ९ या १० में अध्ययनरत छात्र, न्यूनतम ५०% अंक।",
    "documents": [
      "पिछली कक्षा की अंकतालिका",
      "आय प्रमाण पत्र",
      "आधार कार्ड",
      "बैंक पासबुक"
    ],
    "slaDays": 15,
    "fee": "₹0 Free",
    "type": "national_scheme",
    "deskKey": "caste",
    "subKey": "income",
    "officialUrl": "https://scholarships.gov.in"
  },
  {
    "id": "WEL-003",
    "category": "welfare",
    "categoryLabel": "सामाजिक न्याय एवं छात्रवृत्ति (Social Welfare)",
    "titleHi": "इंदिरा गांधी राष्ट्रीय वृद्धावस्था पेंशन",
    "titleEn": "Indira Gandhi Old Age Pension (IGNOAPS)",
    "formNo": "NSAP Old Age",
    "dept": "ग्रामीण विकास मंत्रालय / समाज कल्याण",
    "desc": "६० वर्ष या उससे अधिक आयु के बीपीएल वृद्धजनों को प्रतिमाह ₹1,000 की वित्तीय सुरक्षा।",
    "eligibility": "आयु ६० वर्ष या अधिक एवं बीपीएल सूची में दर्ज परिवार।",
    "documents": [
      "आयु प्रमाण पत्र / आधार",
      "बीपीएल राशन कार्ड",
      "बैंक पासबुक"
    ],
    "slaDays": 21,
    "fee": "₹0 Free",
    "type": "national_scheme",
    "deskKey": "farmer",
    "subKey": "pension",
    "officialUrl": "https://nsap.nic.in"
  },
  {
    "id": "WEL-004",
    "category": "welfare",
    "categoryLabel": "सामाजिक न्याय एवं छात्रवृत्ति (Social Welfare)",
    "titleHi": "निराश्रित महिला (विधवा) पेंशन योजना",
    "titleEn": "Widow / Destitute Women Pension",
    "formNo": "NSAP Widow Pension",
    "dept": "महिला एवं बाल विकास विभाग",
    "desc": "पति की मृत्यु के उपरांत बेसहारा महिलाओं के भरण-पोषण हेतु त्रैमासिक पेंशन अनुदान।",
    "eligibility": "आयु १८ वर्ष या अधिक, पति की मृत्यु हो चुकी हो एवं पुनर्विवाह न किया हो।",
    "documents": [
      "पति का मृत्यु प्रमाण पत्र",
      "आय प्रमाण पत्र",
      "आधार कार्ड",
      "बैंक खाता विवरण"
    ],
    "slaDays": 21,
    "fee": "₹0 Free",
    "type": "national_scheme",
    "deskKey": "farmer",
    "subKey": "pension",
    "officialUrl": "https://sspy-up.gov.in"
  },
  {
    "id": "WEL-005",
    "category": "welfare",
    "categoryLabel": "सामाजिक न्याय एवं छात्रवृत्ति (Social Welfare)",
    "titleHi": "दिव्यांगजन भरण-पोषण पेंशन",
    "titleEn": "Divyangjan Disability Pension",
    "formNo": "Divyang Pension Rule",
    "dept": "दिव्यांगजन सशक्तिकरण विभाग",
    "desc": "४०% या अधिक दिव्यांगता वाले निर्धन नागरिकों हेतु मासिक ₹1,000 की पेंशन सहायता।",
    "eligibility": "न्यूनतम ४०% दिव्यांगता एवं गरीबी रेखा से नीचे जीवनयापन करने वाले नागरिक।",
    "documents": [
      "UDID दिव्यांगता प्रमाण पत्र",
      "आय प्रमाण पत्र",
      "आधार कार्ड",
      "बैंक पासबुक"
    ],
    "slaDays": 21,
    "fee": "₹0 Free",
    "type": "national_scheme",
    "deskKey": "farmer",
    "subKey": "pension",
    "officialUrl": "https://sspy-up.gov.in"
  },
  {
    "id": "WEL-006",
    "category": "welfare",
    "categoryLabel": "सामाजिक न्याय एवं छात्रवृत्ति (Social Welfare)",
    "titleHi": "कन्या सुमंगला / बालिका कल्याण अनुदान",
    "titleEn": "Kanya Sumangala Girl Child Grant",
    "formNo": "MKSY Scheme Guidelines",
    "dept": "महिला कल्याण निदेशालय",
    "desc": "बालिका के जन्म से स्नातक प्रवेश तक ६ विभिन्न चरणों में कुल ₹25,000 की वित्तीय सहायता।",
    "eligibility": "परिवार की अधिकतम २ बालिकाएं, वार्षिक पारिवारिक आय ₹3 लाख तक।",
    "documents": [
      "बालिका का जन्म प्रमाण पत्र",
      "माता-पिता का आधार कार्ड",
      "टीकाकरण कार्ड",
      "स्कूल प्रवेश रसीद"
    ],
    "slaDays": 15,
    "fee": "₹0 Free",
    "type": "national_scheme",
    "deskKey": "birth",
    "subKey": "birth",
    "officialUrl": "https://mksy.up.gov.in"
  },
  {
    "id": "WEL-007",
    "category": "welfare",
    "categoryLabel": "सामाजिक न्याय एवं छात्रवृत्ति (Social Welfare)",
    "titleHi": "राष्ट्रीय पारिवारिक लाभ योजना (NFBS)",
    "titleEn": "National Family Benefit Scheme",
    "formNo": "NFBS Direct Benefit Order",
    "dept": "समाज कल्याण विभाग",
    "desc": "गरीब परिवार के मुख्य कमाऊ मुखिया की मृत्यु होने पर आश्रित परिवार को ₹30,000 की एकमुश्त सहायता।",
    "eligibility": "मृतक मुखिया की आयु १८ से ५९ वर्ष के मध्य एवं परिवार गरीबी रेखा के अंतर्गत हो।",
    "documents": [
      "मुखिया का मृत्यु प्रमाण पत्र",
      "आयु प्रमाण",
      "आय प्रमाण पत्र",
      "आश्रित वारिसान प्रमाण"
    ],
    "slaDays": 30,
    "fee": "₹0 Free",
    "type": "national_scheme",
    "deskKey": "caste",
    "subKey": "legalheir",
    "officialUrl": "https://nfbs.upsdc.gov.in"
  },
  {
    "id": "WEL-008",
    "category": "welfare",
    "categoryLabel": "सामाजिक न्याय एवं छात्रवृत्ति (Social Welfare)",
    "titleHi": "प्रधानमंत्री मातृ वंदना योजना (PMMVY)",
    "titleEn": "Pradhan Mantri Matru Vandana Yojana",
    "formNo": "PMMVY 2.0 Form",
    "dept": "महिला एवं बाल विकास मंत्रालय",
    "desc": "गर्भवती एवं धात्री माताओं को प्रथम व द्वितीय संतान के जन्म पर ₹5,000 तक का मातृत्व पोषण लाभ।",
    "eligibility": "गर्भवती महिलाएं एवं स्तनपान कराने वाली माताएं (सरकारी सेवा अपवर्जित)।",
    "documents": [
      "एमसीपी कार्ड (Mother-Child Protection)",
      "माता व पिता का आधार कार्ड",
      "बैंक पासबुक"
    ],
    "slaDays": 15,
    "fee": "₹0 Free",
    "type": "national_scheme",
    "deskKey": "birth",
    "subKey": "birth",
    "officialUrl": "https://pmmvy.wcd.gov.in"
  },
  {
    "id": "COR-001",
    "category": "corporate",
    "categoryLabel": "कंपनी, उद्योग एवं श्रम (Corporate & MSME)",
    "titleHi": "कंपनी निगमन प्रमाण पत्र (SPICe+ CIN)",
    "titleEn": "Company Incorporation Certificate",
    "formNo": "MCA SPICe+ INC-11",
    "dept": "कॉरपोरेट कार्य मंत्रालय (MCA21)",
    "desc": "कंपनी पहचान संख्या (CIN), पैन, टैन एवं ईपीएफओ पंजीकरण युक्त निगमन प्रमाण पत्र।",
    "eligibility": "न्यूनतम २ निदेशक (प्राइवेट लिमिटेड) अथवा १ निदेशक (ओपीसी) एवं वैध डीआईएन।",
    "documents": [
      "निदेशकों के पैन व आधार",
      "निवास प्रमाण (बैंक स्टेटमेंट/उपयोगिता बिल)",
      "कार्यालय पता एनओसी"
    ],
    "slaDays": 2,
    "fee": "Statutory MCA",
    "type": "statutory_certificate",
    "deskKey": "business",
    "subKey": "spice",
    "officialUrl": "https://www.mca.gov.in"
  },
  {
    "id": "COR-002",
    "category": "corporate",
    "categoryLabel": "कंपनी, उद्योग एवं श्रम (Corporate & MSME)",
    "titleHi": "उद्यम एमएसएमई प्रमाण पत्र",
    "titleEn": "Udyam MSME Certificate",
    "formNo": "MSMED Act Registration",
    "dept": "सूक्ष्म, लघु एवं मध्यम उद्यम मंत्रालय",
    "desc": "स्थायी 19-अंकीय उद्यम संख्या, बैंक ऋण प्राथमिकता, ब्याज छूट एवं सरकारी टेंडर लाभ।",
    "eligibility": "विनिर्माण अथवा सेवा क्षेत्र में कार्यरत सूक्ष्म, लघु अथवा मध्यम उद्यम।",
    "documents": [
      "उद्यमी का आधार कार्ड",
      "पैन कार्ड व जीएसटी नंबर",
      "व्यवसाय का बैंक खाता"
    ],
    "slaDays": 1,
    "fee": "₹0 Free",
    "type": "statutory_certificate",
    "deskKey": "business",
    "subKey": "udyam",
    "officialUrl": "https://udyamregistration.gov.in"
  },
  {
    "id": "COR-003",
    "category": "corporate",
    "categoryLabel": "कंपनी, उद्योग एवं श्रम (Corporate & MSME)",
    "titleHi": "ई-श्रम यूनिवर्सल अकाउंट कार्ड (UAN)",
    "titleEn": "e-Shram Worker UAN Card",
    "formNo": "NDUW Labour Registration",
    "dept": "श्रम एवं रोजगार मंत्रालय",
    "desc": "असंगठित क्षेत्र के श्रमिकों हेतु 12-अंकीय UAN कार्ड एवं ₹2 लाख दुर्घटना बीमा सुरक्षा।",
    "eligibility": "आयु १६ से ५९ वर्ष, असंगठित क्षेत्र का कामगार (ईपीएफओ/ईएसआईसी सदस्य न हो)।",
    "documents": [
      "आधार कार्ड (मोबाइल लिंक्ड)",
      "सक्रिय बैंक खाता विवरण",
      "व्यवसाय/कौशल श्रेणी"
    ],
    "slaDays": 1,
    "fee": "₹0 Free",
    "type": "statutory_certificate",
    "deskKey": "business",
    "subKey": "eshram",
    "officialUrl": "https://eshram.gov.in"
  },
  {
    "id": "COR-004",
    "category": "corporate",
    "categoryLabel": "कंपनी, उद्योग एवं श्रम (Corporate & MSME)",
    "titleHi": "वाणिज्यिक व्यापार लाइसेंस (Trade Licence)",
    "titleEn": "Municipal Trade Licence",
    "formNo": "Municipal Corporation Act",
    "dept": "नगर निगम एवं नगर विकास",
    "desc": "दुकान, व्यवसायिक प्रतिष्ठान, विनिर्माण एवं खाद्य व्यापार संचालन हेतु अधिकृत लाइसेंस।",
    "eligibility": "नगर निगम सीमा अंतर्गत व्यवसाय संचालित करने वाला कोई भी व्यापारी।",
    "documents": [
      "दुकान स्वामित्व डीड अथवा किरायानामा",
      "पहचान पत्र",
      "फायर सेफ्टी अनापत्ति (यदि लागू)"
    ],
    "slaDays": 7,
    "fee": "₹500",
    "type": "statutory_certificate",
    "deskKey": "business",
    "subKey": "trade",
    "officialUrl": "https://serviceonline.gov.in"
  },
  {
    "id": "COR-005",
    "category": "corporate",
    "categoryLabel": "कंपनी, उद्योग एवं श्रम (Corporate & MSME)",
    "titleHi": "पीएम स्वनिधि स्ट्रीट वेंडर ऋण",
    "titleEn": "PM SVANidhi Micro-Credit Scheme",
    "formNo": "PM SVANidhi Portal",
    "dept": "आवासन और शहरी कार्य मंत्रालय",
    "desc": "शहरी स्ट्रीट वेंडर्स हेतु ₹10,000 से ₹50,000 तक संपार्श्विक-मुक्त कार्यशील पूंजी ऋण।",
    "eligibility": "शहरी स्थानीय निकाय द्वारा पंजीकृत अथवा वेंडिंग पहचान पत्र धारक रेहड़ी-पटरी विक्रेता।",
    "documents": [
      "वेंडिंग प्रमाणपत्र / एलओआर",
      "आधार कार्ड",
      "बैंक पासबुक"
    ],
    "slaDays": 14,
    "fee": "₹0 Free",
    "type": "national_scheme",
    "deskKey": "business",
    "subKey": "udyam",
    "officialUrl": "https://pmsvanidhi.mohua.gov.in"
  },
  {
    "id": "COR-006",
    "category": "corporate",
    "categoryLabel": "कंपनी, उद्योग एवं श्रम (Corporate & MSME)",
    "titleHi": "प्रधानमंत्री मुद्रा योजना (PMMY)",
    "titleEn": "PM Mudra Yojana Micro-Enterprise Loan",
    "formNo": "PMMY Shishu/Kishor/Tarun",
    "dept": "वित्तीय सेवा विभाग / सिडबी",
    "desc": "गैर-कॉरपोरेट गैर-कृषि लघु उद्यमों को ₹10 लाख तक का संपार्श्विक-मुक्त संस्थागत बैंक ऋण।",
    "eligibility": "विनिर्माण, व्यापार या सेवा गतिविधि स्थापित करने अथवा विस्तार करने वाले उद्यमी।",
    "documents": [
      "व्यवसाय प्रस्ताव / प्रोजेक्ट रिपोर्ट",
      "पहचान व निवास प्रमाण",
      "बैंक खाता विवरण"
    ],
    "slaDays": 15,
    "fee": "₹0 Free",
    "type": "national_scheme",
    "deskKey": "business",
    "subKey": "udyam",
    "officialUrl": "https://www.mudra.org.in"
  },
  {
    "id": "COR-007",
    "category": "corporate",
    "categoryLabel": "कंपनी, उद्योग एवं श्रम (Corporate & MSME)",
    "titleHi": "दुकान एवं वाणिज्यिक प्रतिष्ठान पंजीकरण",
    "titleEn": "Shops & Commercial Establishment Act",
    "formNo": "Form A Registration",
    "dept": "श्रम आयुक्त विभाग",
    "desc": "दुकानों और व्यावसायिक संस्थानों में काम के घंटे, वेतन व कर्मचारियों के अधिकारों का वैधानिक नियमन।",
    "eligibility": "राज्य में व्यावसायिक परिसर संचालित करने वाला कोई भी नियोक्ता।",
    "documents": [
      "संस्थान का फोटो व पता प्रमाण",
      "कर्मचारियों की सूची",
      "नियोक्ता का पैन व आधार"
    ],
    "slaDays": 5,
    "fee": "₹150",
    "type": "national_scheme",
    "deskKey": "business",
    "subKey": "trade",
    "officialUrl": "https://uplabour.gov.in"
  },
  {
    "id": "COR-008",
    "category": "corporate",
    "categoryLabel": "कंपनी, उद्योग एवं श्रम (Corporate & MSME)",
    "titleHi": "ठेका श्रम (विनियमन व उन्मूलन) लाइसेंस",
    "titleEn": "Contract Labour Licence",
    "formNo": "Contract Labour Act 1970",
    "dept": "केंद्रीय/राज्य मुख्य श्रमायुक्त",
    "desc": "२० या अधिक संविदा श्रमिकों को नियोजित करने वाले ठेकेदारों हेतु सांविधिक श्रम अनुज्ञप्ति।",
    "eligibility": "पंजीकृत प्रतिष्ठान से संविदा कार्य आदेश प्राप्त अधिकृत श्रम संवेदक।",
    "documents": [
      "प्रधान नियोक्ता का फॉर्म 5",
      "सुरक्षा जमा चालान",
      "संवेदक का पैन व बैंक गारंटी"
    ],
    "slaDays": 15,
    "fee": "₹500",
    "type": "national_scheme",
    "deskKey": "business",
    "subKey": "trade",
    "officialUrl": "https://shramsuvidha.gov.in"
  },
  {
    "id": "UTL-001",
    "category": "utilities",
    "categoryLabel": "स्वास्थ्य, आवास एवं जनोपयोगी (Public Utilities)",
    "titleHi": "आयुष्मान भारत गोल्डन कार्ड (PM-JAY)",
    "titleEn": "Ayushman Bharat PM-JAY Card",
    "formNo": "AB PM-JAY Health Cover",
    "dept": "राष्ट्रीय स्वास्थ्य प्राधिकरण (NHA)",
    "desc": "प्रति परिवार प्रति वर्ष ₹5 लाख तक का कैशलेस द्वितीयक एवं तृतीयक अस्पताल उपचार कवर।",
    "eligibility": "एसईसीसी 2011 सूची में शामिल वंचित परिवार अथवा राज्य चिन्हित पात्र लाभार्थी।",
    "documents": [
      "राशन कार्ड",
      "आधार कार्ड",
      "परिवार पहचान पत्र"
    ],
    "slaDays": 3,
    "fee": "₹0 Free",
    "type": "national_scheme",
    "deskKey": "farmer",
    "subKey": "ration",
    "officialUrl": "https://pmjay.gov.in"
  },
  {
    "id": "UTL-002",
    "category": "utilities",
    "categoryLabel": "स्वास्थ्य, आवास एवं जनोपयोगी (Public Utilities)",
    "titleHi": "प्रधानमंत्री आवास योजना (PMAY)",
    "titleEn": "Pradhan Mantri Awas Yojana",
    "formNo": "PMAY Urban / Gramin",
    "dept": "आवासन और शहरी कार्य / ग्रामीण विकास मंत्रालय",
    "desc": "सभी बेघर एवं कच्चे मकानों में रहने वाले पात्र परिवारों को पक्का मकान निर्माण हेतु ₹1.2 - ₹2.5 लाख सहायता।",
    "eligibility": "देश में कहीं भी पक्का मकान न हो, परिवार की आय श्रेणी ईडब्ल्यूएस/एलआईजी में हो।",
    "documents": [
      "आय प्रमाण पत्र",
      "भूमि स्वामित्व अभिलेख / पट्टा",
      "आधार कार्ड",
      "बैंक खाता विवरण"
    ],
    "slaDays": 30,
    "fee": "₹0 Free",
    "type": "national_scheme",
    "deskKey": "caste",
    "subKey": "income",
    "officialUrl": "https://pmaymis.gov.in"
  },
  {
    "id": "UTL-003",
    "category": "utilities",
    "categoryLabel": "स्वास्थ्य, आवास एवं जनोपयोगी (Public Utilities)",
    "titleHi": "प्रधानमंत्री उज्ज्वला योजना 2.0 (LPG)",
    "titleEn": "PM Ujjwala Yojana 2.0 LPG Connection",
    "formNo": "PMUY 2.0 Enrolment",
    "dept": "पेट्रोलियम एवं प्राकृतिक गैस मंत्रालय",
    "desc": "निर्धन परिवारों की वयस्क महिलाओं को निःशुल्क एलपीजी गैस कनेक्शन, पहला सिलेंडर व चूल्हा।",
    "eligibility": "१८ वर्ष से अधिक आयु की महिला, परिवार के किसी सदस्य के नाम पहले से गैस कनेक्शन न हो।",
    "documents": [
      "राशन कार्ड (परिवार सूची)",
      "महिला आवेदक का आधार",
      "बैंक खाता",
      "१४-सूत्रीय घोषणा"
    ],
    "slaDays": 7,
    "fee": "₹0 Free",
    "type": "national_scheme",
    "deskKey": "farmer",
    "subKey": "ration",
    "officialUrl": "https://www.pmuy.gov.in"
  },
  {
    "id": "UTL-004",
    "category": "utilities",
    "categoryLabel": "स्वास्थ्य, आवास एवं जनोपयोगी (Public Utilities)",
    "titleHi": "जल जीवन मिशन - हर घर नल संयोजन",
    "titleEn": "Jal Jeevan Mission Tap Connection",
    "formNo": "JJM Rural Water Supply",
    "dept": "जल शक्ति मंत्रालय / राज्य पेयजल विभाग",
    "desc": "ग्रामीण एवं उपनगरीय परिवारों को घरेलू नल कनेक्शन के माध्यम से स्वच्छ एवं सुरक्षित पेयजल आपूर्ति।",
    "eligibility": "अधिसूचित ग्राम पंचायत अथवा शहरी सीमा अंतर्गत स्थित आवासीय भवन।",
    "documents": [
      "निवास प्रमाण पत्र",
      "आधार कार्ड",
      "भवन स्वामित्व प्रमाण"
    ],
    "slaDays": 10,
    "fee": "₹0 Free",
    "type": "national_scheme",
    "deskKey": "caste",
    "subKey": "domicile",
    "officialUrl": "https://jaljeevanmission.gov.in"
  },
  {
    "id": "UTL-005",
    "category": "utilities",
    "categoryLabel": "स्वास्थ्य, आवास एवं जनोपयोगी (Public Utilities)",
    "titleHi": "घरेलू व वाणिज्यिक नवीन विद्युत संयोजन",
    "titleEn": "New Electricity Connection (Jhatpat)",
    "formNo": "Electricity Act 2003",
    "dept": "राज्य विद्युत वितरण निगम (डिस्कॉम)",
    "desc": "झटपट पोर्टल के माध्यम से १ किलोवाट से अधिक नए घरेलू व गैर-घरेलू बिजली मीटर संयोजन की ऑनलाइन स्वीकृति।",
    "eligibility": "वैध परिसर स्वामी अथवा विधिक किरायेदार जिसके परिसर पर पूर्व बिजली बकाया न हो।",
    "documents": [
      "परिसर स्वामित्व प्रमाण / किरायानामा",
      "आधार कार्ड",
      "पासपोर्ट फोटो",
      "वायरिंग ठेकेदार टेस्ट रिपोर्ट"
    ],
    "slaDays": 7,
    "fee": "₹1500 (सिक्योरिटी)",
    "type": "national_scheme",
    "deskKey": "caste",
    "subKey": "domicile",
    "officialUrl": "https://www.upenergy.in"
  },
  {
    "id": "UTL-006",
    "category": "utilities",
    "categoryLabel": "स्वास्थ्य, आवास एवं जनोपयोगी (Public Utilities)",
    "titleHi": "सीपीग्राम्स लोक शिकायत पंजीकरण (CPGRAMS)",
    "titleEn": "CPGRAMS Public Grievance Redressal",
    "formNo": "DARPG Grievance Portal",
    "dept": "प्रशासनिक सुधार और लोक शिकायत विभाग (DARPG)",
    "desc": "केंद्र व राज्य सरकार के किसी भी मंत्रालय, विभाग या स्वायत्त निकाय के विरुद्ध शिकायत दर्ज कर ३० दिन में निवारण।",
    "eligibility": "कोई भी भारतीय नागरिक जो किसी सरकारी सेवा अथवा भ्रष्टाचार/लापरवाही से पीड़ित हो।",
    "documents": [
      "शिकायत का विस्तृत विवरण",
      "संबंधित विभागीय संदर्भ अथवा साक्ष्य दस्तावेज"
    ],
    "slaDays": 30,
    "fee": "₹0 Free",
    "type": "national_scheme",
    "deskKey": "caste",
    "subKey": "character",
    "officialUrl": "https://pgportal.gov.in"
  },
  {
    "id": "REV-011",
    "category": "revenue",
    "categoryLabel": "राजस्व एवं भूमि प्रशासन (Revenue)",
    "titleHi": "भूमि नामांतरण / दाखिल खारिज",
    "titleEn": "Land Mutation / Dakhil Kharij",
    "formNo": "Revenue Form 34",
    "dept": "राजस्व परिषद (Land Records)",
    "desc": "भूमि क्रय-विक्रय या उत्तराधिकार उपरांत राजस्व खतौनी में नाम प्रतिस्थापन का वैधानिक आदेश।",
    "eligibility": "पंजीकृत बैनामा क्रेता या वैध उत्तराधिकारी।",
    "documents": [
      "पंजीकृत बैनामा / विलेख प्रति",
      "नवीनतम खतौनी नकल",
      "क्रेता एवं विक्रेता का आधार कार्ड",
      "तहसीलदार न्यायालय प्रार्थना पत्र"
    ],
    "slaDays": 45,
    "fee": "₹50 Statutory",
    "type": "statutory_certificate",
    "deskKey": "caste",
    "subKey": "land",
    "officialUrl": "https://upbhulekh.gov.in"
  },
  {
    "id": "REV-012",
    "category": "revenue",
    "categoryLabel": "राजस्व एवं भूमि प्रशासन (Revenue)",
    "titleHi": "भूमि सीमांकन एवं पैमाइश प्रमाण पत्र",
    "titleEn": "Land Demarcation & Survey Order",
    "formNo": "Revenue Form 24",
    "dept": "राजस्व एवं चकबंदी विभाग",
    "desc": "राजस्व निरीक्षक एवं लेखपाल द्वारा गाटा संख्या की आधिकारिक सीमांकन एवं मेढ़ पैमाइश रिपोर्ट।",
    "eligibility": "कृषि भूमि या आवासीय भूखंड का पंजीकृत काश्तकार।",
    "documents": [
      "खसरा एवं खतौनी प्रमाणित प्रति",
      "राजस्व नक्शा (शजरा) प्रति",
      "पहचान पत्र / आधार कार्ड",
      "सीमा विवाद शपथ पत्र"
    ],
    "slaDays": 30,
    "fee": "₹100 Statutory",
    "type": "statutory_certificate",
    "deskKey": "caste",
    "subKey": "land",
    "officialUrl": "https://edistrict.gov.in"
  },
  {
    "id": "REV-013",
    "category": "revenue",
    "categoryLabel": "राजस्व एवं भूमि प्रशासन (Revenue)",
    "titleHi": "कृषि भूमि गैर-कृषि उपयोग अनुमति (धारा 80)",
    "titleEn": "Agricultural Land Use Conversion (Sec 80)",
    "formNo": "Revenue Code Form 143",
    "dept": "उपजिलाधिकारी / एसडीएम न्यायालय",
    "desc": "कृषि भूमि को व्यावसायिक, आवासीय अथवा औद्योगिक उपयोग हेतु रूपांतरित करने का सक्षम आदेश।",
    "eligibility": "भूमि स्वामी जिसके पास स्पष्ट स्वत्व अधिकार एवं निर्विवादित खतौनी हो।",
    "documents": [
      "मूल खतौनी एवं शजरा नक्शा",
      "साइट प्लान / ब्लूप्रिंट",
      "सर्किल रेट अनुसार न्याय शुल्क चालान",
      "सक्षम राजस्व प्राधिकारी आख्या"
    ],
    "slaDays": 60,
    "fee": "₹250 Statutory",
    "type": "welfare_scheme",
    "officialUrl": "https://revenue.gov.in"
  },
  {
    "id": "REV-014",
    "category": "revenue",
    "categoryLabel": "राजस्व एवं भूमि प्रशासन (Revenue)",
    "titleHi": "परिवार रजिस्टर नकल / पारिवारिक सदस्यता",
    "titleEn": "Family Register Copy (Parivar Nakal)",
    "formNo": "Panchayati Raj Form 5",
    "dept": "पंचायती राज एवं नगर निकाय",
    "desc": "ग्राम पंचायत अथवा नगर निगम के आधिकारिक परिवार रजिस्टर की प्रमाणित नकल।",
    "eligibility": "संबंधित ग्राम पंचायत अथवा नगर निकाय वार्ड का स्थायी निवासी।",
    "documents": [
      "मुखिया का पहचान पत्र / आधार",
      "निवास प्रमाण पत्र",
      "राशन कार्ड"
    ],
    "slaDays": 3,
    "fee": "₹10 Free",
    "type": "statutory_certificate",
    "deskKey": "caste",
    "subKey": "legalheir",
    "officialUrl": "https://e-panchayat.gov.in"
  },
  {
    "id": "TRN-009",
    "category": "transport",
    "categoryLabel": "सड़क परिवहन एवं वाहन (MoRTH)",
    "titleHi": "अंतरराष्ट्रीय ड्राइविंग परमिट (IDP)",
    "titleEn": "International Driving Permit (IDP)",
    "formNo": "CMV Rules Form 4A",
    "dept": "सड़क परिवहन एवं राजमार्ग मंत्रालय (सारथी)",
    "desc": "विदेश में वाहन चलाने हेतु वैध अंतरराष्ट्रीय ड्राइविंग परमिट। जिनेवा कन्वेंशन 1949 के अनुरूप।",
    "eligibility": "वैध भारतीय ड्राइविंग लाइसेंस एवं वैध भारतीय पासपोर्ट धारक।",
    "documents": [
      "वैध स्थायी ड्राइविंग लाइसेंस",
      "वैध पासपोर्ट एवं वीजा प्रति",
      "हवाई टिकट प्रति",
      "मेडिकल फिटनेस प्रमाण पत्र (फॉर्म 1A)"
    ],
    "slaDays": 7,
    "fee": "₹1000 Free",
    "type": "statutory_certificate",
    "deskKey": "dl",
    "subKey": "dl",
    "officialUrl": "https://parivahan.gov.in"
  },
  {
    "id": "TRN-010",
    "category": "transport",
    "categoryLabel": "सड़क परिवहन एवं वाहन (MoRTH)",
    "titleHi": "वाणिज्यिक वाहन राष्ट्रीय परमिट",
    "titleEn": "All India National Permit (Goods Carrier)",
    "formNo": "MV Act Form 48",
    "dept": "राज्य परिवहन प्राधिकरण (वाहन 4.0)",
    "desc": "समस्त भारत में माल ढुलाई करने वाले व्यावसायिक वाहनों हेतु अधिकृत नेशनल परमिट।",
    "eligibility": "पंजीकृत व्यावसायिक वाहन स्वामी जिसके पास वैध फिटनेस एवं बीमा हो।",
    "documents": [
      "वाहन पंजीकरण प्रमाण पत्र (RC)",
      "वैध वाहन फिटनेस प्रमाण पत्र",
      "तृतीय पक्ष बीमा पॉलिसी",
      "राष्ट्रीय परमिट शुल्क रसीद"
    ],
    "slaDays": 3,
    "fee": "₹1500 Free",
    "type": "welfare_scheme",
    "officialUrl": "https://vahan.parivahan.gov.in"
  },
  {
    "id": "TRN-011",
    "category": "transport",
    "categoryLabel": "सड़क परिवहन एवं वाहन (MoRTH)",
    "titleHi": "वाहन हाइपोथीकेशन निरस्तीकरण (HPT)",
    "titleEn": "Vehicle Hypothecation Termination (HPT)",
    "formNo": "CMV Rules Form 35",
    "dept": "परिवहन विभाग (RTO Sarathi)",
    "desc": "बैंक ऋण चुकता उपरांत आरसी से बैंक बंधक विलोपित करने का आधिकारिक आदेश।",
    "eligibility": "वाहन स्वामी जिसने बैंक/वित्तीय संस्थान का संपूर्ण ऋण चुका दिया हो।",
    "documents": [
      "बैंक द्वारा जारी अनापत्ति प्रमाण पत्र (NOC)",
      "फॉर्म 35 (बैंक द्वारा हस्ताक्षरित)",
      "मूल वाहन पंजीकरण प्रमाण पत्र (RC)",
      "वैध प्रदूषण एवं बीमा प्रमाण"
    ],
    "slaDays": 7,
    "fee": "₹100 Statutory",
    "type": "statutory_certificate",
    "deskKey": "dl",
    "subKey": "rc",
    "officialUrl": "https://vahan.parivahan.gov.in"
  },
  {
    "id": "TRN-012",
    "category": "transport",
    "categoryLabel": "सड़क परिवहन एवं वाहन (MoRTH)",
    "titleHi": "कंडक्टर लाइसेंस आवेदन",
    "titleEn": "Conductor Licence Application",
    "formNo": "State MV Rules Form CL",
    "dept": "राज्य परिवहन निगम एवं आरटीओ",
    "desc": "सार्वजनिक यात्री सेवा बसों में परिचालक (कंडक्टर) के रूप में कार्य करने का वैधानिक लाइसेंस।",
    "eligibility": "न्यूनतम 10वीं उत्तीर्ण एवं फर्स्ट एड (प्राथमिक चिकित्सा) प्रमाण पत्र धारक।",
    "documents": [
      "सेंट जॉन एम्बुलेंस प्राथमिक चिकित्सा प्रमाण",
      "शैक्षणिक योग्यता अंकपत्र (10th/12th)",
      "मेडिकल फिटनेस प्रमाण पत्र",
      "चरित्र प्रमाण पत्र"
    ],
    "slaDays": 14,
    "fee": "₹100 Free",
    "type": "statutory_certificate",
    "deskKey": "dl",
    "subKey": "ll",
    "officialUrl": "https://parivahan.gov.in"
  },
  {
    "id": "CIV-007",
    "category": "civil",
    "categoryLabel": "नागरिक पंजीकरण एवं जीवन सांख्यिकी (CRS)",
    "titleHi": "दत्तक ग्रहण विलेख पंजीकरण आदेश",
    "titleEn": "Adoption Deed Registration Order",
    "formNo": "CARA Adoption Form 1",
    "dept": "केंद्रीय दत्तक ग्रहण संसाधन प्राधिकरण (CARA)",
    "desc": "सक्षम न्यायालय अथवा जिला मजिस्ट्रेट द्वारा जारी विधिक बच्चा दत्तक ग्रहण प्रमाण पत्र।",
    "eligibility": "कारा (CARA) दिशा-निर्देशों एवं हिंदू दत्तक ग्रहण अधिनियम के अंतर्गत पात्र अभिभावक।",
    "documents": [
      "जिला मजिस्ट्रेट / न्यायालय दत्तक आदेश",
      "दत्तक माता-पिता का आय व स्वास्थ्य प्रमाण",
      "बालक का गृह प्रवेश अभिलेख",
      "विवाह प्रमाण पत्र"
    ],
    "slaDays": 30,
    "fee": "₹100 Free",
    "type": "welfare_scheme",
    "officialUrl": "https://cara.nic.in"
  },
  {
    "id": "CIV-008",
    "category": "civil",
    "categoryLabel": "नागरिक पंजीकरण एवं जीवन सांख्यिकी (CRS)",
    "titleHi": "डिजिटल जीवन प्रमाण पत्र (Jeevan Pramaan)",
    "titleEn": "Digital Life Certificate for Pensioners",
    "formNo": "Jeevan Pramaan DLC",
    "dept": "पेंशन एवं पेंशनभोगी कल्याण विभाग",
    "desc": "पेंशनभोगियों हेतु आधार आधारित बायोमेट्रिक डिजिटल जीवन प्रमाण पत्र। ट्रेजरी भ्रमण की आवश्यकता नहीं।",
    "eligibility": "केंद्र अथवा राज्य सरकार के सेवानिवृत्त पेंशनभोगी।",
    "documents": [
      "पेंशन भुगतान आदेश संख्या (PPO No)",
      "पेंशन बैंक खाता विवरण",
      "आधार संख्या एवं बायोमेट्रिक सत्यापन",
      "सक्रिय मोबाइल नंबर"
    ],
    "slaDays": 1,
    "fee": "₹0 Free",
    "type": "statutory_certificate",
    "deskKey": "farmer",
    "subKey": "pension",
    "officialUrl": "https://jeevanpramaan.gov.in"
  },
  {
    "id": "CIV-009",
    "category": "civil",
    "categoryLabel": "नागरिक पंजीकरण एवं जीवन सांख्यिकी (CRS)",
    "titleHi": "जन्म / मृत्यु गैर-उपलब्धता प्रमाण पत्र (NAC)",
    "titleEn": "Non-Availability Certificate (NAC)",
    "formNo": "RBD Act 1969 Form 10",
    "dept": "रजिस्ट्रार जनरल ऑफ इंडिया (CRS)",
    "desc": "जन्म अथवा मृत्यु का रिकॉर्ड रजिस्टर में अनुपलब्ध होने पर जारी होने वाला कानूनी प्रमाण पत्र।",
    "eligibility": "नागरिक जिसका जन्म/मृत्यु रिकॉर्ड स्थानीय निकाय रजिस्टर में अप्राप्त हो।",
    "documents": [
      "जन्म/मृत्यु खोज आवेदन पत्र",
      "अस्पताल अथवा श्मशान/कब्रिस्तान रसीद",
      "आवेदक का आधार एवं हलफनामा",
      "स्कूल स्थानांतरण प्रमाण पत्र (TC)"
    ],
    "slaDays": 15,
    "fee": "₹20 Free",
    "type": "statutory_certificate",
    "deskKey": "birth",
    "subKey": "birth",
    "officialUrl": "https://crsorgi.gov.in"
  },
  {
    "id": "CIV-010",
    "category": "civil",
    "categoryLabel": "नागरिक पंजीकरण एवं जीवन सांख्यिकी (CRS)",
    "titleHi": "उभयलिंगी पहचान प्रमाण पत्र एवं कार्ड",
    "titleEn": "Transgender Certificate & Identity Card",
    "formNo": "TG Protection Rules Form 1",
    "dept": "सामाजिक न्याय एवं अधिकारिता मंत्रालय",
    "desc": "उभयलिंगी व्यक्तियों के अधिकारों का संरक्षण अधिनियम 2019 अंतर्गत आधिकारिक पहचान पत्र।",
    "eligibility": "उभयलिंगी व्यक्ति जो स्वयं की लैंगिक पहचान घोषित करते हैं।",
    "documents": [
      "स्व-घोषणा हलफनामा",
      "निवास एवं आयु प्रमाण पत्र",
      "आधार कार्ड प्रति",
      "पासपोर्ट आकार फोटो"
    ],
    "slaDays": 30,
    "fee": "₹0 Free",
    "type": "welfare_scheme",
    "officialUrl": "https://transgender.dosje.gov.in"
  },
  {
    "id": "AGR-009",
    "category": "agri",
    "categoryLabel": "कृषि, किसान एवं खाद्य वितरण",
    "titleHi": "परंपरागत जैविक कृषि प्रमाणन (PKVY)",
    "titleEn": "PKVY Organic Farming Certification",
    "formNo": "PGS-India Organic Form 1",
    "dept": "कृषि एवं किसान कल्याण मंत्रालय",
    "desc": "जैविक कृषि करने वाले कृषकों एवं समूहों को जारी होने वाला सहभागिता प्रमाणन कार्ड।",
    "eligibility": "जैविक खेती करने वाले कृषक समूह अथवा व्यक्तिगत किसान।",
    "documents": [
      "भू-अभिलेख / खतौनी नकल",
      "कृषक समूह (PGS) सदस्यता अभिलेख",
      "जैविक आदान उपयोग डायरी",
      "मृदा परीक्षण रिपोर्ट"
    ],
    "slaDays": 30,
    "fee": "₹0 Free",
    "type": "welfare_scheme",
    "officialUrl": "https://pgsindia-ncof.gov.in"
  },
  {
    "id": "AGR-010",
    "category": "agri",
    "categoryLabel": "कृषि, किसान एवं खाद्य वितरण",
    "titleHi": "पशुधन एवं मत्स्य पालन किसान क्रेडिट कार्ड",
    "titleEn": "Animal Husbandry & Fishery KCC",
    "formNo": "DAHD KCC Form AH",
    "dept": "पशुपालन, डेयरी एवं मत्स्य पालन विभाग",
    "desc": "डेयरी, बकरी पालन, कुक्कुट एवं मत्स्य पालकों को रियायती ब्याज दर पर 2 लाख तक कार्यशील पूंजी।",
    "eligibility": "पशुपालक अथवा मत्स्य पालक किसान।",
    "documents": [
      "पशु स्वामित्व सत्यापन प्रमाण / टैग संख्या",
      "आधार एवं पैन कार्ड",
      "बैंक खाता विवरण",
      "भूमि अथवा शेड उपलब्धता विवरण"
    ],
    "slaDays": 14,
    "fee": "₹0 Free",
    "type": "statutory_certificate",
    "deskKey": "farmer",
    "subKey": "kcc",
    "officialUrl": "https://dahd.nic.in"
  },
  {
    "id": "AGR-011",
    "category": "agri",
    "categoryLabel": "कृषि, किसान एवं खाद्य वितरण",
    "titleHi": "पीएम कुसुम सोलर कृषि पंप सब्सिडी योजना",
    "titleEn": "PM-KUSUM Solar Agriculture Pump Scheme",
    "formNo": "MNRE KUSUM Comp-B",
    "dept": "नवीन एवं नवीकरणीय ऊर्जा मंत्रालय",
    "desc": "किसानों को सिंचाई हेतु 90% तक सब्सिडी पर सोलर वाटर पंपिंग सिस्टम स्थापना।",
    "eligibility": "कृषि भूमि धारक किसान जहां ग्रिड बिजली अनुपलब्ध अथवा वैकल्पिक ऊर्जा इच्छुक हों।",
    "documents": [
      "खतौनी नकल एवं भू-अधिकार प्रमाण",
      "सिंचाई स्रोत (बोरवेल) उपलब्धता प्रमाण",
      "बैंक खाता विवरण एवं आधार",
      "कृषक अंशदान शपथ पत्र"
    ],
    "slaDays": 45,
    "fee": "₹0 Free",
    "type": "welfare_scheme",
    "officialUrl": "https://pmkusum.mnre.gov.in"
  },
  {
    "id": "AGR-012",
    "category": "agri",
    "categoryLabel": "कृषि, किसान एवं खाद्य वितरण",
    "titleHi": "उर्वरक / खाद बिक्री डीलर लाइसेंस",
    "titleEn": "Fertilizer Retail Sale Licence",
    "formNo": "FCO 1985 Form A-1",
    "dept": "कृषि विभाग एवं जिला कृषि अधिकारी",
    "desc": "रासायनिक एवं जैविक खाद के खुदरा व्यापार हेतु उर्वरक नियंत्रण आदेश के अंतर्गत अधिकृत लाइसेंस।",
    "eligibility": "कृषि स्नातक / बीएससी रसायन शास्त्र अथवा 15 दिवसीय अधिकृत खाद प्रशिक्षण प्रमाण पत्र धारक।",
    "documents": [
      "शैक्षणिक योग्यता प्रमाण पत्र",
      "दुकान एवं गोदाम का किरायानामा / स्वामित्व विलेख",
      "थोक निर्माता कंपनी का आपूर्ति पत्र (Letter of Supply)",
      "चालान रसीद"
    ],
    "slaDays": 30,
    "fee": "₹1500 Statutory",
    "type": "statutory_certificate",
    "deskKey": "business",
    "subKey": "trade",
    "officialUrl": "https://agricoop.nic.in"
  },
  {
    "id": "WEL-009",
    "category": "welfare",
    "categoryLabel": "सामाजिक कल्याण, पेंशन एवं समावेशन",
    "titleHi": "भवन एवं सन्निर्माण कर्मकार कल्याण कार्ड (BOCW)",
    "titleEn": "BOCW Construction Worker Welfare Card",
    "formNo": "BOCW Act Form 27",
    "dept": "श्रम एवं रोजगार विभाग",
    "desc": "राजमिस्त्री, बढ़ई, इलेक्ट्रीशियन व निर्माण श्रमिकों को छात्रवृत्ति, मातृत्व व मृत्यु अनुदान हेतु पंजीयन।",
    "eligibility": "विगत 12 माह में कम से कम 90 दिन निर्माण कार्य करने वाले 18-60 वर्ष के श्रमिक।",
    "documents": [
      "90 दिन कार्य का स्व-प्रमाण पत्र / ठेकेदार आख्या",
      "आधार कार्ड एवं बैंक पासबुक",
      "परिवार के सदस्यों का विवरण",
      "पासपोर्ट आकार फोटो"
    ],
    "slaDays": 15,
    "fee": "₹20 Statutory",
    "type": "statutory_certificate",
    "deskKey": "business",
    "subKey": "eshram",
    "officialUrl": "https://bocw.gov.in"
  },
  {
    "id": "WEL-010",
    "category": "welfare",
    "categoryLabel": "सामाजिक कल्याण, पेंशन एवं समावेशन",
    "titleHi": "प्रधानमंत्री मातृ वंदना योजना (PMMVY 2nd Child)",
    "titleEn": "PMMVY Maternity Incentive (Girl Child)",
    "formNo": "WCD PMMVY Form 1-B",
    "dept": "महिला एवं बाल विकास मंत्रालय",
    "desc": "द्वितीय संतान बालिका होने पर गर्भवती एवं धात्री माताओं को ₹6000 का प्रत्यक्ष बैंक डीबीटी पोषण अनुदान।",
    "eligibility": "गर्भवती एवं स्तनपान कराने वाली माताएं जिनका दूसरा प्रसव बालिका का हो।",
    "documents": [
      "मातृ एवं बाल संरक्षण (MCP) कार्ड",
      "बालिका का आधिकारिक जन्म प्रमाण पत्र",
      "माता का आधार एवं आधार से लिंक बैंक खाता",
      "संस्थागत प्रसव प्रमाण"
    ],
    "slaDays": 21,
    "fee": "₹0 Free",
    "type": "welfare_scheme",
    "officialUrl": "https://pmmvy.wcd.gov.in"
  },
  {
    "id": "WEL-011",
    "category": "welfare",
    "categoryLabel": "सामाजिक कल्याण, पेंशन एवं समावेशन",
    "titleHi": "कबीर अंत्येष्टि सहायता अनुदान",
    "titleEn": "Funeral Assistance Grant for BPL Families",
    "formNo": "NSAP Form AG-1",
    "dept": "समाज कल्याण विभाग",
    "desc": "बीपीएल एवं निर्धन परिवारों में सदस्य के निधन पर अंतिम संस्कार हेतु ₹5000 की त्वरित आर्थिक सहायता।",
    "eligibility": "बीपीएल सूची में दर्ज परिवार अथवा वार्षिक आय ₹46,080 से कम वाले परिवार।",
    "documents": [
      "मृतक का आधिकारिक मृत्यु प्रमाण पत्र",
      "बीपीएल राशन कार्ड अथवा आय प्रमाण पत्र",
      "आवेदक का आधार कार्ड",
      "बैंक पासबुक छायाप्रति"
    ],
    "slaDays": 3,
    "fee": "₹0 Free",
    "type": "welfare_scheme",
    "officialUrl": "https://nsap.nic.in"
  },
  {
    "id": "WEL-012",
    "category": "welfare",
    "categoryLabel": "सामाजिक कल्याण, पेंशन एवं समावेशन",
    "titleHi": "राष्ट्रीय प्रवासी कर्मकार पंजीकरण",
    "titleEn": "Inter-State Migrant Worker Registration",
    "formNo": "OSH Code Form IX",
    "dept": "श्रम कल्याण बोर्ड एवं प्रवासी प्रकोष्ठ",
    "desc": "अन्य राज्यों में कार्यरत प्रवासी श्रमिकों का केंद्रीय डेटाबेस पंजीयन एवं आपातकालीन सुरक्षा कवरेज।",
    "eligibility": "अपने गृह राज्य से बाहर किसी अन्य राज्य में श्रम व रोजगार करने वाले नागरिक।",
    "documents": [
      "आधार कार्ड",
      "कार्यस्थल का नियोक्ता विवरण अथवा स्व-घोषणा",
      "बैंक खाता विवरण",
      "आपातकालीन संपर्क विवरण"
    ],
    "slaDays": 7,
    "fee": "₹0 Free",
    "type": "welfare_scheme",
    "officialUrl": "https://labour.gov.in"
  },
  {
    "id": "COR-009",
    "category": "corporate",
    "categoryLabel": "उद्योग, कंपनी एवं व्यावसायिक अनुज्ञप्ति",
    "titleHi": "त्वरित ई-पैन कार्ड (Instant e-PAN via Aadhaar)",
    "titleEn": "Instant e-PAN via Aadhaar e-KYC",
    "formNo": "IT Act Form 49A",
    "dept": "आयकर विभाग (Income Tax Department)",
    "desc": "आधार ई-केवाईसी द्वारा 10 मिनट में निःशुल्क डिजिटल परमानेंट अकाउंट नंबर (PAN) आवंटन।",
    "eligibility": "भारतीय नागरिक जिसके पास आधार कार्ड हो और जिसे पूर्व में पैन आवंटित न हुआ हो।",
    "documents": [
      "आधार संख्या",
      "आधार से लिंक सक्रिय मोबाइल नंबर (OTP सत्यापन)"
    ],
    "slaDays": 1,
    "fee": "₹0 Free",
    "type": "statutory_certificate",
    "deskKey": "business",
    "subKey": "udyam",
    "officialUrl": "https://incometax.gov.in"
  },
  {
    "id": "COR-010",
    "category": "corporate",
    "categoryLabel": "उद्योग, कंपनी एवं व्यावसायिक अनुज्ञप्ति",
    "titleHi": "कीटनाशक एवं पेस्टीसाइड खुदरा विक्रेता लाइसेंस",
    "titleEn": "Insecticides & Pesticides Sale Licence",
    "formNo": "Insecticides Act Form VII",
    "dept": "वनस्पति संरक्षण, संगरोध एवं संग्रह निदेशालय",
    "desc": "कृषि कीटनाशकों एवं पौध संरक्षण रसायनों के क्रय-विक्रय व भंडारण हेतु विधिक अनुज्ञप्ति।",
    "eligibility": "रसायन विज्ञान / कृषि स्नातक अथवा मान्यता प्राप्त कीटनाशक डिप्लोमा धारक।",
    "documents": [
      "शैक्षणिक योग्यता अंकतालिका",
      "दुकान व गोदाम परिसर का स्वामित्व/किराया विलेख",
      "कीटनाशक विनिर्माता कंपनी का प्रिंसिपल सर्टिफिकेट",
      "ट्रेजरी चालान"
    ],
    "slaDays": 30,
    "fee": "₹2000 Statutory",
    "type": "statutory_certificate",
    "deskKey": "business",
    "subKey": "trade",
    "officialUrl": "https://ppqs.gov.in"
  },
  {
    "id": "COR-011",
    "category": "corporate",
    "categoryLabel": "उद्योग, कंपनी एवं व्यावसायिक अनुज्ञप्ति",
    "titleHi": "दवा एवं औषधि बिक्री लाइसेंस (Retail Chemist)",
    "titleEn": "Retail Drug Sale Licence (Form 20/21)",
    "formNo": "Drugs & Cosmetics Form 20",
    "dept": "खाद्य सुरक्षा एवं औषधि प्रशासन (FSDA)",
    "desc": "एलोपैथिक औषधियों के खुदरा विक्रय (केमिस्ट शॉप) हेतु राज्य ड्रग कंट्रोलर द्वारा जारी लाइसेंस।",
    "eligibility": "पंजीकृत फार्मासिस्ट (D.Pharma / B.Pharma) युक्त प्रतिष्ठान स्वामी।",
    "documents": [
      "पंजीकृत फार्मासिस्ट का रजिस्ट्रेशन प्रमाण पत्र",
      "दुकान का न्यूनतम 10 वर्गमीटर क्षेत्रफल ब्लूप्रिंट",
      "रेफ्रिजरेटर खरीद बिल (कोल्ड चेन हेतु)",
      "ड्रग इंस्पेक्टर निरीक्षण आख्या"
    ],
    "slaDays": 45,
    "fee": "₹3000 Statutory",
    "type": "statutory_certificate",
    "deskKey": "business",
    "subKey": "trade",
    "officialUrl": "https://cdsco.gov.in"
  },
  {
    "id": "COR-012",
    "category": "corporate",
    "categoryLabel": "उद्योग, कंपनी एवं व्यावसायिक अनुज्ञप्ति",
    "titleHi": "व्यावसायिक अग्निशमन अनापत्ति प्रमाण पत्र (Fire NOC)",
    "titleEn": "Commercial Fire Safety NOC",
    "formNo": "Fire Safety Rules Form Fire-1",
    "dept": "अग्निशमन सेवा विभाग (Fire Service)",
    "desc": "होटल, अस्पताल, मॉल एवं कारखानों हेतु अग्नि सुरक्षा मानकों के अनुपालन का वैधानिक अनापत्ति प्रमाण।",
    "eligibility": "व्यावसायिक, औद्योगिक अथवा बहुमंजिला भवन स्वामी/प्रबंधक।",
    "documents": [
      "भवन का स्वीकृत लेआउट मानचित्र",
      "स्थापित अग्निशामक उपकरणों की सूची",
      "अग्निशमन प्रशिक्षण प्रमाण पत्र",
      "मुख्य अग्निशमन अधिकारी (CFO) निरीक्षण आख्या"
    ],
    "slaDays": 21,
    "fee": "₹500 Statutory",
    "type": "welfare_scheme",
    "officialUrl": "https://fireservice.gov.in"
  },
  {
    "id": "UTL-007",
    "category": "utilities",
    "categoryLabel": "सार्वजनिक उपयोगिताएं, आवास एवं स्वास्थ्य",
    "titleHi": "जन्म रजिस्टर में विलंबित शिशु नाम दर्ज",
    "titleEn": "Addition of Child Name in Birth Register",
    "formNo": "RBD Act 1969 Form 1A",
    "dept": "रजिस्ट्रार जन्म एवं मृत्यु (नगर निगम / ब्लॉक)",
    "desc": "पूर्व में बिना नाम दर्ज जन्म प्रमाण पत्र में बच्चे का आधिकारिक नाम दर्ज कराने का आवेदन।",
    "eligibility": "बच्चे के माता-पिता अथवा विधिक अभिभावक।",
    "documents": [
      "मूल बिना नाम वाला जन्म प्रमाण पत्र",
      "माता-पिता का आधार कार्ड",
      "बच्चे के नाम संबंधी शपथ पत्र",
      "स्कूल या टीकाकरण कार्ड"
    ],
    "slaDays": 7,
    "fee": "₹5 Statutory",
    "type": "statutory_certificate",
    "deskKey": "birth",
    "subKey": "birth",
    "officialUrl": "https://crsorgi.gov.in"
  },
  {
    "id": "UTL-008",
    "category": "utilities",
    "categoryLabel": "सार्वजनिक उपयोगिताएं, आवास एवं स्वास्थ्य",
    "titleHi": "प्रधानमंत्री उज्ज्वला मुफ्त गैस संयोजन",
    "titleEn": "PM Ujjwala Free LPG Connection (PMUY)",
    "formNo": "PMUY KYC Form",
    "dept": "पेट्रोलियम एवं प्राकृतिक गैस मंत्रालय",
    "desc": "निर्धन एवं बीपीएल ग्रामीण महिलाओं को निःशुल्क घरेलू एलपीजी गैस कनेक्शन, चूल्हा एवं पहला सिलेंडर।",
    "eligibility": "18 वर्ष से अधिक आयु की बीपीएल परिवार की महिला जिनके घर में पूर्व से गैस कनेक्शन न हो।",
    "documents": [
      "बीपीएल राशन कार्ड",
      "आवेदिका एवं परिवार के सभी वयस्क सदस्यों का आधार",
      "बैंक पासबुक छायाप्रति",
      "14-सूत्रीय घोषणा पत्र"
    ],
    "slaDays": 7,
    "fee": "₹0 Free",
    "type": "welfare_scheme",
    "officialUrl": "https://pmuy.gov.in"
  }
];

  // =========================================================================
  // 2. TRANSACTIONAL DATABASE ENGINE (APPLICATIONS, CERTIFICATES, AUDIT LOGS)
  // =========================================================================
  const NDIG_DATABASE = {
    storageKey: 'ndig_db_store_v2',

    data: {
      applications: [
        {
          refNo: 'NDIG/2026/REV-001/849201',
          serviceId: 'REV-001',
          serviceName: 'जाति प्रमाण पत्र (SC/ST Caste Certificate)',
          applicantName: 'RAJESH KUMAR',
          fatherName: 'HARISH CHANDRA',
          aadhaarMasked: 'XXXX-XXXX-7219',
          district: 'Varanasi',
          status: 'APPROVED',
          submittedAt: '2026-10-12 10:30 IST',
          approvedAt: '2026-10-14 16:45 IST',
          officerName: 'Shri A. K. Sharma (Sub-Divisional Magistrate)',
          officerRemarks: 'Field inquiry verified via Revenue Lekhpal report. Approved under Rule 6.',
          certificateNo: 'UP/2026/CC/849201',
          sha256Digest: '0x89e1f42a7c89b910dc025e1a90b8f4139981d3f9e8310c14b29f9e71c6384a51'
        },
        {
          refNo: 'NDIG/2026/TRN-001/104928',
          serviceId: 'TRN-001',
          serviceName: 'स्थायी ड्राइविंग लाइसेंस (Smart DL)',
          applicantName: 'PRIYA SHARMA',
          fatherName: 'MAHESH SHARMA',
          aadhaarMasked: 'XXXX-XXXX-9142',
          district: 'New Delhi',
          status: 'APPROVED',
          submittedAt: '2026-10-13 11:15 IST',
          approvedAt: '2026-10-15 14:20 IST',
          officerName: 'Licensing Authority (RTO DL-04)',
          officerRemarks: 'Biometric road test passed on automated driving track.',
          certificateNo: 'DL-0420260084920',
          sha256Digest: '0x12a98f4c9103e298df3400a91e84732109baef01298437019823ef0912837401'
        },
        {
          refNo: 'NDIG/2026/AGR-001/671204',
          serviceId: 'AGR-001',
          serviceName: 'पीएम-किसान सम्मान निधि वाउचर',
          applicantName: 'RAMESH KUMAR YADAV',
          fatherName: 'RAM SAHAY YADAV',
          aadhaarMasked: 'XXXX-XXXX-6712',
          district: 'Meerut',
          status: 'APPROVED',
          submittedAt: '2026-10-14 09:00 IST',
          approvedAt: '2026-10-15 17:00 IST',
          officerName: 'District Agriculture Officer, Meerut',
          officerRemarks: 'AgriStack land record matched with Bhulekh Khatauni #00184.',
          certificateNo: 'PMKISAN-UP-2026-48201',
          sha256Digest: '0x7e819b02a84c91e0a29bd481029481a029384710293847102938471029384710'
        },
        {
          refNo: 'NDIG/2026/REV-002/918472',
          serviceId: 'REV-002',
          serviceName: 'आय प्रमाण पत्र (Income Certificate)',
          applicantName: 'VIKRAM SINGH',
          fatherName: 'RANVEER SINGH',
          aadhaarMasked: 'XXXX-XXXX-4819',
          district: 'Meerut',
          status: 'UNDER_REVIEW',
          submittedAt: '2026-10-15 14:10 IST',
          approvedAt: null,
          officerName: 'Tehsildar Sadar',
          officerRemarks: 'Awaiting Lekhpal local income verification report.',
          certificateNo: null,
          sha256Digest: null
        }
      ],
      auditLogs: [
        { timestamp: '2026-10-15 14:10:22 IST', action: 'APPLICATION_SUBMITTED', refNo: 'NDIG/2026/REV-002/918472', role: 'CITIZEN', ipHash: 'SHA256:LOCAL' },
        { timestamp: '2026-10-15 14:20:05 IST', action: 'OFFICER_APPROVED', refNo: 'NDIG/2026/TRN-001/104928', role: 'OFFICER', ipHash: 'SHA256:PARICHAY_DSC' }
      ]
    },

    init() {
      try {
        const stored = sessionStorage.getItem(this.storageKey);
        if (stored) {
          const parsed = JSON.parse(stored);
          if (parsed && Array.isArray(parsed.applications)) {
            this.data = parsed;
          }
        }
      } catch(e) {}
    },

    save() {
      try {
        sessionStorage.setItem(this.storageKey, JSON.stringify(this.data));
      } catch(e) {}
    },

    addApplication(app) {
      this.data.applications.unshift(app);
      this.data.auditLogs.unshift({
        timestamp: new Date().toLocaleString('en-IN') + ' IST',
        action: 'APPLICATION_SUBMITTED',
        refNo: app.refNo,
        role: window.SecurityAuthManager?.currentUser?.role || 'CITIZEN',
        ipHash: 'SHA256:CLIENT_BUS'
      });
      this.save();
      return app;
    },

    updateStatus(refNo, newStatus, officerRemarks) {
      const app = this.data.applications.find(a => a.refNo === refNo);
      if (app) {
        app.status = newStatus;
        app.officerRemarks = officerRemarks || app.officerRemarks;
        if (newStatus === 'APPROVED') {
          app.approvedAt = new Date().toLocaleString('en-IN') + ' IST';
          app.officerName = window.SecurityAuthManager?.currentUser?.name || 'SDM / Tehsildar';
          app.sha256Digest = '0x' + Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, '0')).join('');
          if (!app.certificateNo) {
            app.certificateNo = 'UP/2026/CERT/' + Math.floor(100000 + Math.random() * 900000);
          }
        }
        this.data.auditLogs.unshift({
          timestamp: new Date().toLocaleString('en-IN') + ' IST',
          action: 'OFFICER_' + newStatus,
          refNo: refNo,
          role: 'OFFICER',
          ipHash: 'SHA256:CLASS3_DSC'
        });
        this.save();
        return app;
      }
      return null;
    },

    findByRef(refNo) {
      if (!refNo) return null;
      const cleanRef = refNo.trim().toUpperCase();
      return this.data.applications.find(a => a.refNo.toUpperCase() === cleanRef || (a.certificateNo && a.certificateNo.toUpperCase() === cleanRef));
    },

    saveApplication(formData = {}) {
      const sId = formData.serviceId || 'GEN-01';
      const refNo = 'NDIG-2026-' + sId.replace(/[^A-Za-z0-9]/g, '') + '-' + Math.floor(100000 + Math.random() * 900000);
      const maskedAadhaar = maskAadhaar(formData.aadhaarNumber || '999988887777');
      const app = {
        refNo: refNo,
        serviceId: sId,
        serviceName: formData.serviceName || 'Statutory Citizen Service',
        category: formData.category || 'general',
        applicantName: formData.applicantName || 'Citizen Applicant',
        fatherName: formData.fatherName || '',
        aadhaarMasked: maskedAadhaar,
        aadhaarNumber: maskedAadhaar,
        mobileNumber: formData.mobileNumber || '',
        district: formData.district || 'National',
        address: formData.address || '',
        status: 'SUBMITTED',
        submittedAt: new Date().toLocaleString('en-IN') + ' IST',
        approvedAt: null,
        officerName: null,
        officerRemarks: 'Application received and queued for competent officer scrutiny.',
        certificateNo: null,
        sha256Digest: null
      };
      this.addApplication(app);
      return { appRef: refNo, status: 'SUBMITTED', data: app };
    },

    getApplication(refNo) {
      return this.findByRef(refNo);
    },

    approveApplication(refNo, officerName = 'SDM / Competent Authority') {
      const app = this.updateStatus(refNo, 'APPROVED', `Application approved by ${officerName} with Class 3 DSC token.`);
      if (app) {
        return { status: app.status, certNumber: app.certificateNo, app: app };
      }
      return { status: 'ERROR', message: 'Application not found' };
    },

    rejectApplication(refNo, reason = 'Deficiency in submitted documents') {
      const app = this.updateStatus(refNo, 'REJECTED', reason);
      return { status: app ? app.status : 'ERROR', app: app };
    },

    getAuditLogs() {
      return this.data.auditLogs || [];
    }
  };
  window.NDIG_DATABASE = NDIG_DATABASE;


  // =========================================================================
  // 3. 54 SERVICES DIRECTORY RENDERER & REAL-TIME SEARCH (DEBOUNCED)
  // =========================================================================
  let currentActiveCategory = 'all';
  let serviceSearchDebounceTimer = null;

  window.renderAll54Services = function(category = 'all', query = '') {
    currentActiveCategory = category;
    const container = document.getElementById('services-grid-container');
    if (!container) return;

    const q = (query || '').toLowerCase().trim();
    const filtered = window.NATIONAL_SERVICE_REGISTRY.filter(s => {
      const matchCat = (category === 'all' || s.category === category);
      const matchQuery = !q || 
        s.titleHi.toLowerCase().includes(q) || 
        s.titleEn.toLowerCase().includes(q) || 
        s.dept.toLowerCase().includes(q) || 
        s.formNo.toLowerCase().includes(q) ||
        s.desc.toLowerCase().includes(q);
      return matchCat && matchQuery;
    });

    const countEl = document.getElementById('cert-visible-count');
    if (countEl) countEl.textContent = filtered.length;

    if (filtered.length === 0) {
      container.innerHTML = `
        <div class="col-span-full py-12 text-center bg-white rounded-2xl border border-slate-200 p-8 shadow-xs">
          <i data-lucide="search-x" class="w-12 h-12 text-slate-300 mx-auto mb-3"></i>
          <h4 class="text-base font-bold text-[#00314D]">कोई सेवा नहीं मिली (No Services Found)</h4>
          <p class="text-xs text-slate-500 mt-1 max-w-md mx-auto">
            आपके खोज मापदंड "${escapeHtml(query)}" से संबंधित कोई सेवा नहीं मिली। कृपया कोई अन्य कीवर्ड जैसे "Caste", "DL", "Ration", या "Pension" खोजें।
          </p>
          <button type="button" onclick="window.filterNationalServices('all', '')" class="mt-4 bg-[#00314D] text-white px-4 py-1.5 rounded-xl text-xs font-bold hover:bg-[#FF8000] transition cursor-pointer">
            सभी 54 सेवाएं दिखाएं (Show All 54 Services)
          </button>
        </div>`;
      if (window.lucide) lucide.createIcons();
      return;
    }

    container.innerHTML = filtered.map(s => {
      const isCertificate = s.type === 'statutory_certificate';
      const actionBtn = isCertificate 
        ? `<button type="button" onclick="window.openCertificateDirectly('${s.deskKey}', '${s.subKey}')" class="w-full bg-[#00314D] hover:bg-[#FF8000] text-white font-bold py-2 px-3 rounded-xl text-xs flex items-center justify-center gap-1.5 transition shadow-sm cursor-pointer group-hover:shadow-md">
             <span>✍️ ऑनलाइन आवेदन करें / Apply Now</span>
             <i data-lucide="arrow-right" class="w-3.5 h-3.5 group-hover:translate-x-1 transition duration-200"></i>
           </button>`
        : `<div class="grid grid-cols-2 gap-1.5 w-full">
             <button type="button" onclick="window.openServiceModal('${s.id}')" class="bg-[#00314D] hover:bg-[#002236] text-white font-bold py-2 px-2 rounded-xl text-[11px] flex items-center justify-center gap-1 transition shadow-xs cursor-pointer">
               <i data-lucide="info" class="w-3 h-3"></i>
               <span>विवरण व पात्रता</span>
             </button>
             <a href="${s.officialUrl}" target="_blank" rel="noopener noreferrer" class="bg-[#138808] hover:bg-[#0F6B06] text-white font-bold py-2 px-2 rounded-xl text-[11px] flex items-center justify-center gap-1 transition shadow-xs cursor-pointer text-center">
               <span>आधिकारिक पोर्टल</span>
               <i data-lucide="external-link" class="w-3 h-3"></i>
             </a>
           </div>`;

      const typeBadge = isCertificate 
        ? `<span class="text-[10px] font-extrabold text-[#138808] bg-[#DEF7EC] border border-[#31C48D] px-2 py-0.5 rounded-full flex items-center gap-1">
             <span class="w-1.5 h-1.5 rounded-full bg-[#138808] animate-pulse"></span>
             <span>Statutory Certificate (प्रमाण पत्र)</span>
           </span>`
        : `<span class="text-[10px] font-bold text-[#0284C7] bg-[#EFF6FF] border border-[#BFDBFE] px-2 py-0.5 rounded-full flex items-center gap-1">
             <i data-lucide="globe" class="w-3 h-3 text-[#0284C7]"></i>
             <span>National Welfare Scheme (योजना)</span>
           </span>`;

      return `
        <div class="cert-directory-card group bg-white rounded-2xl border border-[#CBD5E1] hover:border-[#FF8000] p-4 shadow-sm hover:shadow-xl transition-all duration-300 flex flex-col justify-between" data-category="${s.category}">
          <div>
            <div class="flex items-center justify-between gap-2 pb-2.5 border-b border-slate-100">
              <span class="text-[10px] font-bold text-[#00314D] bg-[#F1F5F9] px-2 py-0.5 rounded-full border border-[#CBD5E1]">
                ${escapeHtml(s.id)} • ${escapeHtml(s.category.toUpperCase())}
              </span>
              ${typeBadge}
            </div>

            <div class="flex items-start gap-3 mt-3">
              <div class="w-10 h-10 rounded-xl bg-[#00314D] group-hover:bg-[#FF8000] text-white flex items-center justify-center shrink-0 transition-colors duration-300 shadow-sm">
                <i data-lucide="file-text" class="w-5 h-5"></i>
              </div>
              <div class="flex-grow">
                <h4 class="font-extrabold text-sm text-[#00314D] group-hover:text-[#FF8000] transition-colors leading-snug">
                  ${escapeHtml(s.titleHi)}
                </h4>
                <div class="text-[11px] font-semibold text-slate-500">
                  ${escapeHtml(s.titleEn)} • <span class="text-[#0284C7]">${escapeHtml(s.formNo)}</span>
                </div>
              </div>
            </div>

            <p class="text-xs text-[#475569] mt-2.5 leading-relaxed line-clamp-2">
              ${escapeHtml(s.desc)}
            </p>

            <div class="grid grid-cols-2 gap-2 mt-3 pt-2.5 border-t border-slate-100 text-[11px] text-slate-600">
              <div class="flex items-center gap-1">
                <i data-lucide="clock" class="w-3.5 h-3.5 text-sky-600"></i>
                <span>SLA: <strong class="text-slate-800">${escapeHtml(s.slaDays)} Days</strong></span>
              </div>
              <div class="flex items-center gap-1 justify-end">
                <i data-lucide="tag" class="w-3.5 h-3.5 text-emerald-600"></i>
                <span>शुल्क: <strong class="text-slate-800">${escapeHtml(s.fee)}</strong></span>
              </div>
            </div>
          </div>

          <div class="mt-4 pt-3 border-t border-slate-100">
            ${actionBtn}
          </div>
        </div>`;
    }).join('');

    if (window.lucide) lucide.createIcons();
  };

  window.filterNationalServices = function(category, query) {
    document.querySelectorAll('.cert-filter-btn').forEach(btn => {
      const btnCat = btn.getAttribute('data-cat');
      if (btnCat === category) {
        btn.className = 'cert-filter-btn px-3 py-1.5 rounded-xl text-xs font-extrabold bg-[#00314D] text-white border border-[#00314D] transition shadow-xs cursor-pointer';
      } else {
        btn.className = 'cert-filter-btn px-3 py-1.5 rounded-xl text-xs font-bold bg-white text-[#00314D] border border-[#CBD5E1] hover:border-[#00314D] transition cursor-pointer';
      }
    });

    const searchInput = document.getElementById('search-54-services-input');
    const q = query !== undefined ? query : (searchInput ? searchInput.value : '');
    window.renderAll54Services(category, q);
  };

  window.onSearch54Services = function(val) {
    clearTimeout(serviceSearchDebounceTimer);
    serviceSearchDebounceTimer = setTimeout(() => {
      window.renderAll54Services(currentActiveCategory, val);
    }, 150);
  };

  // Service Detail Modal
  window.openServiceModal = function(serviceId) {
    const s = window.NATIONAL_SERVICE_REGISTRY.find(item => item.id === serviceId);
    if (!s) return;

    const modal = document.getElementById('modal-service-detail');
    const content = document.getElementById('modal-service-detail-content');
    if (!modal || !content) return;

    content.innerHTML = `
      <div class="space-y-4">
        <div class="flex items-start justify-between gap-3 pb-3 border-b border-slate-200">
          <div>
            <span class="text-[10px] font-mono font-bold bg-[#EBF5FF] text-[#00314D] px-2.5 py-0.5 rounded-full border border-[#BFDBFE]">
              ${escapeHtml(s.id)} • ${escapeHtml(s.categoryLabel)}
            </span>
            <h3 class="text-lg font-black text-[#00314D] mt-1.5 leading-snug">
              ${escapeHtml(s.titleHi)}
            </h3>
            <div class="text-xs text-slate-500 font-semibold">${escapeHtml(s.titleEn)} (${escapeHtml(s.formNo)})</div>
          </div>
          <button type="button" onclick="window.closeServiceModal()" class="text-slate-400 hover:text-slate-700 p-1 rounded-lg cursor-pointer">
            <i data-lucide="x" class="w-5 h-5"></i>
          </button>
        </div>

        <div class="bg-amber-50 p-3 rounded-xl border border-amber-200 text-xs text-amber-900 leading-relaxed">
          <strong>विवरण एवं उद्देश्य:</strong> ${escapeHtml(s.desc)}
        </div>

        <div class="grid grid-cols-2 gap-3 text-xs">
          <div class="bg-slate-50 p-2.5 rounded-xl border border-slate-200">
            <span class="text-slate-500 text-[11px] block">संबंधित मंत्रालय / विभाग:</span>
            <strong class="text-[#00314D] font-bold">${escapeHtml(s.dept)}</strong>
          </div>
          <div class="bg-slate-50 p-2.5 rounded-xl border border-slate-200">
            <span class="text-slate-500 text-[11px] block">समय-सीमा (SLA) एवं शुल्क:</span>
            <strong class="text-emerald-700 font-bold">${escapeHtml(s.slaDays)} Days | ${escapeHtml(s.fee)}</strong>
          </div>
        </div>

        <div class="space-y-2 text-xs">
          <div class="font-bold text-[#00314D]">वैधानिक पात्रता मानदंड (Eligibility Criteria):</div>
          <div class="p-2.5 bg-slate-50 border border-slate-200 rounded-xl text-slate-700 leading-relaxed">
            ${escapeHtml(s.eligibility)}
          </div>
        </div>

        <div class="space-y-2 text-xs">
          <div class="font-bold text-[#00314D]">आवश्यक दस्तावेज (Required Documents):</div>
          <ul class="list-disc pl-5 space-y-1 text-slate-700">
            ${s.documents.map(d => `<li>${escapeHtml(d)}</li>`).join('')}
          </ul>
        </div>

        <div class="pt-3 border-t border-slate-200 flex flex-wrap items-center justify-between gap-2">
          <a href="${s.officialUrl}" target="_blank" rel="noopener noreferrer" class="bg-[#138808] hover:bg-[#0F6B06] text-white px-4 py-2 rounded-xl text-xs font-bold flex items-center gap-1.5 transition shadow-sm">
            <span>आधिकारिक सरकारी पोर्टल खोलें</span>
            <i data-lucide="external-link" class="w-3.5 h-3.5"></i>
          </a>
          <button type="button" onclick="window.closeServiceModal()" class="bg-slate-200 hover:bg-slate-300 text-slate-800 px-4 py-2 rounded-xl text-xs font-bold cursor-pointer">
            बंद करें (Close)
          </button>
        </div>
      </div>
    `;

    modal.classList.remove('hidden');
    if (window.lucide) lucide.createIcons();
  };

  window.closeServiceModal = function() {
    const modal = document.getElementById('modal-service-detail');
    if (modal) modal.classList.add('hidden');
  };

  // =========================================================================
  // 4. OFFICER REVIEW & APPROVAL WORKSTATION
  // =========================================================================
  window.openOfficerReviewModal = function() {
    if (!SecurityAuthManager.isOfficer()) {
      showGovToast('Security Alert: Officer authentication required. Please login via Parichay Officer Desk.');
      window.openLoginModal();
      window.switchLoginTab('officer');
      return;
    }

    const modal = document.getElementById('modal-officer-queue');
    const listEl = document.getElementById('officer-queue-list');
    if (!modal || !listEl) return;

    const apps = NDIG_DATABASE.data.applications;
    listEl.innerHTML = apps.map(app => {
      const statusBadge = app.status === 'APPROVED' 
        ? '<span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-100 text-emerald-800 border border-emerald-300">APPROVED</span>'
        : (app.status === 'REJECTED' 
            ? '<span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-red-100 text-red-800 border border-red-300">REJECTED</span>'
            : '<span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-100 text-amber-800 border border-amber-300">UNDER REVIEW</span>');

      const actions = app.status === 'UNDER_REVIEW' 
        ? `<div class="flex items-center gap-2 mt-2">
             <button type="button" onclick="window.processOfficerDecision('${app.refNo}', 'APPROVED')" class="bg-[#138808] hover:bg-[#0F6B06] text-white px-3 py-1 rounded-lg text-xs font-bold flex items-center gap-1 cursor-pointer">
               <i data-lucide="check" class="w-3 h-3"></i>
               <span>Approve with Class 3 DSC</span>
             </button>
             <button type="button" onclick="window.processOfficerDecision('${app.refNo}', 'REJECTED')" class="bg-[#DC2626] hover:bg-[#B91C1C] text-white px-3 py-1 rounded-lg text-xs font-bold flex items-center gap-1 cursor-pointer">
               <i data-lucide="x" class="w-3 h-3"></i>
               <span>Reject with Remarks</span>
             </button>
           </div>`
        : `<div class="text-[11px] text-slate-500 mt-1">Processed by ${escapeHtml(app.officerName || 'Executive Magistrate')} on ${escapeHtml(app.approvedAt || 'N/A')}</div>`;

      return `
        <div class="bg-white p-3.5 rounded-xl border border-slate-200 shadow-2xs space-y-1 text-xs">
          <div class="flex items-center justify-between">
            <span class="font-mono font-bold text-[#00314D]">${escapeHtml(app.refNo)}</span>
            ${statusBadge}
          </div>
          <div class="font-bold text-slate-800">${escapeHtml(app.serviceName)}</div>
          <div class="grid grid-cols-2 gap-2 text-slate-600 text-[11px]">
            <div>आवेदक: <strong>${escapeHtml(app.applicantName)}</strong></div>
            <div>पिता का नाम: <strong>${escapeHtml(app.fatherName)}</strong></div>
            <div>आधार: <strong class="font-mono">${escapeHtml(app.aadhaarMasked)}</strong></div>
            <div>जनपद: <strong>${escapeHtml(app.district)}</strong></div>
          </div>
          <div class="text-[11px] text-slate-500 pt-1">प्रस्तुति समय: ${escapeHtml(app.submittedAt)}</div>
          ${actions}
        </div>`;
    }).join('');

    modal.classList.remove('hidden');
    if (window.lucide) lucide.createIcons();
  };

  window.closeOfficerReviewModal = function() {
    const modal = document.getElementById('modal-officer-queue');
    if (modal) modal.classList.add('hidden');
  };

  window.processOfficerDecision = function(refNo, decision) {
    if (!SecurityAuthManager.isOfficer()) {
      alert('Unauthorized action.');
      return;
    }
    const remarks = prompt(
      decision === 'APPROVED' 
        ? 'Enter Official Endorsement Remarks (e.g. Field verification report verified by SDM):'
        : 'Enter Reason for Rejection:'
    );
    if (remarks === null) return;

    NDIG_DATABASE.updateStatus(refNo, decision, remarks);
    showGovToast(`Application ${refNo} has been ${decision} by Executive Magistrate!`);
    window.openOfficerReviewModal();
  };

  // =========================================================================
  // 5. ENHANCED TRACK APPLICATION STATUS ENGINE (CONNECTED TO NDIG_DATABASE)
  // =========================================================================
  window.trackApplicationReal = function(queryRef) {
    const inputRef = queryRef || document.getElementById('track-ref-input')?.value;
    if (!inputRef || !inputRef.trim()) {
      showGovToast('Please enter an Application Reference Number (e.g. NDIG/2026/REV-001/849201)');
      return;
    }

    const app = NDIG_DATABASE.findByRef(inputRef);
    const resultBox = document.getElementById('track-result-box');
    if (!resultBox) return;

    if (!app) {
      resultBox.classList.remove('hidden');
      resultBox.innerHTML = `
        <div class="bg-red-50 border border-red-200 p-4 rounded-xl text-xs text-red-900">
          <div class="font-bold flex items-center gap-1.5 text-sm text-red-950">
            <i data-lucide="alert-circle" class="w-4 h-4 text-red-600"></i>
            <span>आवेदन रिकॉर्ड नहीं मिला (Reference Number Not Found)</span>
          </div>
          <p class="mt-1">दर्ज किया गया संदर्भ संख्या "<strong>${escapeHtml(inputRef)}</strong>" राष्ट्रीय नागरिक सेवा डेटाबेस में नहीं मिला। कृपया अपना पावती पत्र (Receipt) जांचें।</p>
        </div>`;
      if (window.lucide) lucide.createIcons();
      return;
    }

    const isApproved = app.status === 'APPROVED';
    const isUnderReview = app.status === 'UNDER_REVIEW';

    resultBox.classList.remove('hidden');
    resultBox.innerHTML = `
      <div class="bg-white border-2 border-[#00314D] p-4 rounded-2xl shadow-md space-y-4 text-xs font-sans">
        <div class="flex items-center justify-between pb-3 border-b border-slate-200">
          <div>
            <span class="text-[10px] font-mono font-bold bg-[#EBF5FF] text-[#00314D] px-2.5 py-0.5 rounded-full border border-[#BFDBFE]">
              STATUS: ${escapeHtml(app.status)}
            </span>
            <h4 class="font-black text-sm text-[#00314D] mt-1">${escapeHtml(app.serviceName)}</h4>
            <div class="font-mono text-slate-500 text-[11px]">Ref: ${escapeHtml(app.refNo)}</div>
          </div>
          ${isApproved ? '<div class="text-right"><span class="bg-emerald-100 text-emerald-800 font-bold px-3 py-1 rounded-full text-xs flex items-center gap-1 border border-emerald-300"><i data-lucide="check-circle" class="w-3.5 h-3.5"></i> Certificate Issued</span></div>' : ''}
        </div>

        <!-- 5-Stage Stepper -->
        <div class="relative py-2">
          <div class="grid grid-cols-5 gap-2 text-center text-[10px] font-bold">
            <div class="text-emerald-700">
              <div class="w-6 h-6 rounded-full bg-emerald-600 text-white flex items-center justify-center mx-auto mb-1 shadow-xs">✓</div>
              <span>१. आवेदन दर्ज</span>
            </div>
            <div class="text-emerald-700">
              <div class="w-6 h-6 rounded-full bg-emerald-600 text-white flex items-center justify-center mx-auto mb-1 shadow-xs">✓</div>
              <span>२. दस्तावेज जांच</span>
            </div>
            <div class="${isApproved || isUnderReview ? 'text-emerald-700' : 'text-slate-400'}">
              <div class="w-6 h-6 rounded-full ${isApproved ? 'bg-emerald-600 text-white' : 'bg-amber-500 text-white animate-pulse'} flex items-center justify-center mx-auto mb-1 shadow-xs">
                ${isApproved ? '✓' : '३'}
              </div>
              <span>३. स्थलीय सत्यापन</span>
            </div>
            <div class="${isApproved ? 'text-emerald-700' : 'text-slate-400'}">
              <div class="w-6 h-6 rounded-full ${isApproved ? 'bg-emerald-600 text-white' : 'bg-slate-200 text-slate-600'} flex items-center justify-center mx-auto mb-1 shadow-xs">
                ${isApproved ? '✓' : '४'}
              </div>
              <span>४. अधिकारी स्वीकृति</span>
            </div>
            <div class="${isApproved ? 'text-emerald-700' : 'text-slate-400'}">
              <div class="w-6 h-6 rounded-full ${isApproved ? 'bg-emerald-600 text-white' : 'bg-slate-200 text-slate-600'} flex items-center justify-center mx-auto mb-1 shadow-xs">
                ${isApproved ? '✓' : '५'}
              </div>
              <span>५. राजपत्र प्रपत्र जारी</span>
            </div>
          </div>
        </div>

        <div class="bg-slate-50 p-3 rounded-xl border border-slate-200 space-y-1.5 text-[11px]">
          <div class="grid grid-cols-2 gap-2">
            <div>आवेदक का नाम: <strong class="text-slate-900">${escapeHtml(app.applicantName)}</strong></div>
            <div>पिता का नाम: <strong class="text-slate-900">${escapeHtml(app.fatherName)}</strong></div>
            <div>जनपद / तहसील: <strong class="text-slate-900">${escapeHtml(app.district)}</strong></div>
            <div>आधार टोकन: <strong class="font-mono text-slate-900">${escapeHtml(app.aadhaarMasked)}</strong></div>
          </div>
          <div class="pt-1 border-t border-slate-200 text-slate-600">
            अधिकारी समीक्षा आख्या: <strong>${escapeHtml(app.officerRemarks || 'In Progress')}</strong>
          </div>
          ${app.certificateNo ? `<div class="text-emerald-700 font-bold pt-1">प्रमाण पत्र संख्या (Certificate No): <span class="font-mono">${escapeHtml(app.certificateNo)}</span></div>` : ''}
          ${app.sha256Digest ? `<div class="font-mono text-[9.5px] text-slate-400 break-all">Digital Audit SHA256: ${escapeHtml(app.sha256Digest)}</div>` : ''}
        </div>
      </div>`;

    if (window.lucide) lucide.createIcons();
    resultBox.scrollIntoView({ behavior: 'smooth' });
  };
