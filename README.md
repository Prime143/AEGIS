<div align="center">
  <img width="1200" height="475" alt="GHBanner" src="https://github.com/user-attachments/assets/0aa67016-6eaf-458a-adb2-6e31a0763ed6" />
  <h1>🛡️ AEGIS - Job Scam Shield</h1>
  <p><i>An Enterprise-Grade AI Governance and Security Platform. Built for the Google Solution Challenge 2026.</i></p>
</div>

---

## 👥 Team Kaalnetra
- **Vijay Ukande** (Team Lead)
- **Sakshi Shimple**
- **Darshan P**
- **Rohan Dede**

---

## 🎯 About the Project

**AEGIS** is a standalone, production-ready application that leverages the power of Google's advanced AI models to provide multimodal document redaction, security governance, and an intelligent SOC (Security Operations Center) dashboard. Its core real-world application acts as a "Job Scam Shield"—identifying red flags in dubious job offers, protecting user data, and fostering a community-driven scam reporting pipeline.

### The Problem
The rise of sophisticated job scams disproportionately affects vulnerable job seekers globally, leading to financial loss and data theft. Traditional security platforms lack the multimodal AI intelligence necessary to scan nuanced documents, images, and communications effectively.

### The Solution
AEGIS brings enterprise-grade AI governance directly to users through an intuitive, localized interface featuring a cyberpunk aesthetic. It provides:
1. **Multimodal Analysis:** Intelligent scanning of job documents and descriptions using Gemini to detect fraudulent intent.
2. **SOC Admin Dashboard:** High-level overview and insights of potential ongoing scams and governance risks.
3. **Community Hub:** Real-time (in-memory) scam reporting and community discussion to crowdsource security awareness.

### UN Sustainable Development Goals (SDGs) Targeted
- **Goal 8:** Decent Work and Economic Growth
- **Goal 16:** Peace, Justice and Strong Institutions

---

## 🛠 Tech Stack & Google Technologies

- **Frontend:** React 19, Vite, Tailwind CSS v4, Framer Motion
- **Backend:** Node.js, Express, TypeScript
- **Google Technologies:**
  - **Google Gemini API (`@google/genai`):** Used as the core intelligence engine for multimodal document redaction, job description analysis, and scam flagging.

---

## 🚀 Quick Start / How to Run

### Prerequisites
- [Node.js](https://nodejs.org/en/) (v18 or higher)
- A Google Gemini API Key.

### Local Setup Instructions

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Prime143/AEGIS.git
   cd AEGIS
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Configure Environment Variables:**
   - Copy `.env.example` to `.env.local` (or `.env`).
   - Add your Google Gemini API Key inside the file:
     ```env
     GEMINI_API_KEY="your_actual_gemini_api_key_here"
     ```

4. **Run the Application:**
   ```bash
   npm run dev
   ```
   *This starts the local development server and provides a local URL (typically `http://localhost:5173`) to view the app.*

---

## 📺 Demo Video
*(Link your unlisted YouTube demo video here)*  
[Watch Trial Demo Placeholder]

---

## 📄 License
This project is structured for the Google Solution Challenge 2026. Code provided under the standard MIT License.
