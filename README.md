<div align="center">
  <img width="1200" height="475" alt="GHBanner" src="https://github.com/user-attachments/assets/0aa67016-6eaf-458a-adb2-6e31a0763ed6" />
  <h1>🛡️ AEGIS: Enterprise AI Risk Governance Gateway</h1>
  <p><i>Building secure infrastructure for the responsible adoption of AI.</i></p>
</div>

---

## 🎯 Project Overview: AEGIS

**AEGIS** is an Enterprise AI Risk Governance Gateway designed to act as a security layer between corporate employees and third-party AI models (like Gemini, ChatGPT, or Claude). It addresses the "Shadow AI" problem—where employees accidentally leak sensitive company data while using AI tools.

## 🛠️ Key Technical Pillars

### 1. AI-Powered Intent Analysis
- Uses **Gemini 2.5 Flash** to analyze user prompts in real-time.
- It identifies the "intent" behind a query to determine if it violates corporate security policies before the request ever reaches the external AI.

### 2. Dynamic PII Sanitization & Redaction
- Automatically detects and masks Personally Identifiable Information (PII) like names, emails, API keys, and financial data.
- Ensures that only "sanitized" data is sent to the cloud, maintaining compliance with data privacy laws.

### 3. Risk Governance Dashboard
- Provides administrators with a high-level view of AI usage across the organization.
- Logs blocked attempts and high-risk prompts to help security teams refine their defense strategies.

### 4. Deployment & Scalability
- The prototype is currently deployed on **Render** (with explored Vercel case studies for impact analysis).
- The architecture is built to handle enterprise-level traffic with low latency.

---

## 🌍 Alignment with UN Sustainable Development Goals

Your submission specifically targets:

- **Goal 9 (Industry, Innovation, and Infrastructure):** By building secure infrastructure for the responsible adoption of AI.
- **Goal 8 (Decent Work and Economic Growth):** By protecting the digital integrity of businesses and preventing costly data breaches.

---

## 🚀 Quick Start / How to Run

### Prerequisites
- [Node.js](https://nodejs.org/en/) (v18 or higher)
- A Google Gemini API Key

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
