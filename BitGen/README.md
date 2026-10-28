# National Digital Interoperability Gateway (NDIG)
> **Official Architecture:** Unified Citizen Lifecycle & Enterprise Service Interoperability Platform under the Ministry of Electronics & IT (MeitY), Government of India. Designed in compliance with IndEA 2.0, Open API Policy, DPDP Act 2023, and GIGW 3.0 accessibility standards.

### System Integration and Interoperability among Government Digital Platforms
**Division:** National e-Governance Division (NeGD) | **Platform:** NDIG Enterprise Gateway v2.4

---

## 📌 Project Overview
This project is a digital public infrastructure (DPI) concept showcase and interactive demo built for **Smart India Hackathon (SIH) 2026**. It solves the critical bottleneck of disconnected government digital platforms by establishing an interoperable middleware layer, standardized RESTful APIs (aligned with Government of India's Open API Policy & API Setu), zero-trust security, and a unified single life-event citizen interface.

---

## 🚀 Key Features

1. **Interactive Interoperability Sandbox & Simulator**:
   - Live simulations for complex multi-agency citizen life events:
     - *Newborn Child Registration* (Health Dept + Municipal Corporation + UIDAI Baal Aadhaar)
     - *Single-Window Business Incorporation* (MCA SPICe+ + GSTN + EPFO/ESIC + Bank API)
     - *Direct Benefit Transfer (DBT) Subsidy* (PM-KISAN + State Bhulekh Land Records + PFMS + NPCI AePS)
   - Real-time packet telemetry, simulated latency monitoring, and immutable SHA-256 audit logging.

2. **8 Technical Pillars Architecture**:
   - API-based integration adapters for legacy databases.
   - Enterprise middleware integration layer.
   - Standardized JSON-LD 1.1 / OpenAPI schemas.
   - Centralized IAM with Single Sign-On (e-Pramaan / DigiLocker).
   - Real-time event-driven synchronization.
   - Zero-Trust model with AES-256-GCM payload encryption.
   - Centralized OpenTelemetry & Prometheus monitoring.
   - Cloud-native, scalable Kubernetes container architecture.

3. **Feasibility & Operational Viability Matrix**:
   - Executive comparison of Technical Feasibility vs. Operational Viability across 4 key dimensions.
   - Interactive Administrative ROI Estimator (demonstrating ~40% operational savings).

4. **National Policy & Standards Grounding**:
   - Grounded in Government of India Open API Policy, API Setu technical documentation, and Digital India standards.

---

## 🛠️ Tech Stack & Architecture
- **Frontend Core:** Pure Semantic HTML5, Vanilla ES6 JavaScript (Zero runtime bloat).
- **Styling & Aesthetics:** Modern Tailwind CSS + Custom GovTech Design Tokens.
- **Iconography:** Lucide Icons.
- **Portability:** 100% Client-side and static — runs instantly in any modern browser with zero server setup or complex build configurations.

---

## 🌐 Instant Local Launch & Deployment

### Run Locally:
Simply open `index.html` in any web browser (Chrome, Edge, Firefox, Safari).

Alternatively, run a lightweight local HTTP server using Python:
```bash
python -m http.server 8080
```
Then navigate to `http://localhost:8080`.

### Deploy to GitHub Pages:
1. Push this folder to a GitHub repository.
2. In repository settings, navigate to **Pages**.
3. Under **Branch**, select `main` (or `master`) and directory `/ (root)`.
4. Click **Save**. Your site will be live instantly!

### Deploy to Vercel / Netlify:
- Drag and drop this folder onto the **Netlify** or **Vercel** dashboard, or connect the GitHub repository. It deploys automatically with zero build configuration.

---

## 👥 Authors
- **Team BitGen** (Team ID: 194847)
- Smart India Hackathon 2026

