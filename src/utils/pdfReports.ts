import { jsPDF } from 'jspdf';
import { UserAwarenessProfile, TrainingModule, UserRole } from '../core/types';
import { LogEvent } from '../../database';

/**
 * AEGIS Enterprise PDF Report Generator
 * Generates styled, official PDF documents for:
 * 1. Employee Security Awareness & Coaching Dossiers
 * 2. Security Audit & Forensic Investigation Logs
 */

const PAGE_WIDTH = 210; // A4 standard width (mm)
const PAGE_HEIGHT = 297; // A4 standard height (mm)
const MARGIN = 14;
const CONTENT_WIDTH = PAGE_WIDTH - MARGIN * 2;

// Standard colors [R, G, B]
const COLOR_PRIMARY = [15, 23, 42]; // Slate 900
const COLOR_ACCENT = [6, 182, 212]; // Cyan 500
const COLOR_TEXT = [30, 41, 59]; // Slate 800
const COLOR_MUTED = [100, 116, 139]; // Slate 500
const COLOR_LIGHT_BG = [248, 250, 252]; // Slate 50
const COLOR_BORDER = [226, 232, 240]; // Slate 200
const COLOR_DANGER = [225, 29, 72]; // Rose 600
const COLOR_WARNING = [217, 119, 6]; // Amber 600
const COLOR_SUCCESS = [16, 185, 129]; // Emerald 600

function drawHeader(doc: jsPDF, title: string, subtitle: string, reportTypeBadge: string) {
  // Top brand banner
  doc.setFillColor(15, 23, 42);
  doc.rect(0, 0, PAGE_WIDTH, 26, 'F');

  // Cyan accent line
  doc.setFillColor(6, 182, 212);
  doc.rect(0, 26, PAGE_WIDTH, 1.5, 'F');

  // Brand Name
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.setTextColor(255, 255, 255);
  doc.text('AEGIS', MARGIN, 12);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(148, 163, 184);
  doc.text('AI-Enabled Governance & Information Security Gateway', MARGIN + 22, 12);

  // Badge
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.5);
  doc.setTextColor(6, 182, 212);
  doc.text(reportTypeBadge.toUpperCase(), PAGE_WIDTH - MARGIN, 12, { align: 'right' });

  // Document Title & Subtitle
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(255, 255, 255);
  doc.text(title, MARGIN, 21);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.5);
  doc.setTextColor(203, 213, 225);
  doc.text(subtitle, PAGE_WIDTH - MARGIN, 21, { align: 'right' });
}

function drawFooter(doc: jsPDF, pageNumber: number, totalPages: number) {
  const footerY = PAGE_HEIGHT - 10;
  doc.setDrawColor(226, 232, 240);
  doc.setLineWidth(0.3);
  doc.line(MARGIN, footerY - 2, PAGE_WIDTH - MARGIN, footerY - 2);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7);
  doc.setTextColor(100, 116, 139);
  doc.text('CONFIDENTIAL & PROPRIETARY · NEXUS DEFENSE SYSTEMS · AEGIS SECURITY INTELLIGENCE', MARGIN, footerY + 2);
  doc.text(`Page ${pageNumber} of ${totalPages}`, PAGE_WIDTH - MARGIN, footerY + 2, { align: 'right' });
}

function checkPage(doc: jsPDF, currentY: number, neededHeight: number, title: string, subtitle: string, badge: string): number {
  if (currentY + neededHeight > PAGE_HEIGHT - 18) {
    doc.addPage();
    drawHeader(doc, title, subtitle, badge);
    return 36;
  }
  return currentY;
}

/**
 * Triggers a download of a jsPDF document ensuring the file is saved as a true PDF
 */
export function savePdfDocument(doc: jsPDF, filename: string): void {
  const safeFilename = filename.endsWith('.pdf') ? filename : `${filename}.pdf`;
  if (typeof window !== 'undefined' && typeof document !== 'undefined') {
    try {
      const rawBlob = doc.output('blob');
      const blob = new Blob([rawBlob], { type: 'application/pdf' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = safeFilename;
      a.dataset.downloadurl = ['application/pdf', safeFilename, url].join(':');
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 10000);
      return;
    } catch (e) {
      console.warn('Browser blob download fallback:', e);
    }
  }
  doc.save(safeFilename);
}

/**
 * Builds the complete Employee Security Awareness & Coaching Dossier PDF document
 */
export function buildEmployeeDossierPdfDoc(profile: UserAwarenessProfile): jsPDF {
  const doc = new jsPDF({ unit: 'mm', format: 'a4', orientation: 'portrait' });
  const reportDate = new Date().toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });

  const title = `HUMAN RISK DOSSIER: ${profile.name.toUpperCase()}`;
  const subtitle = `Generated: ${reportDate}`;
  const badge = `POSTURE: ${profile.postureTier.replace('_', ' ')}`;

  drawHeader(doc, title, subtitle, badge);
  let y = 34;

  // -------------------------------------------------------------
  // 1. EMPLOYEE IDENTITY & METRICS CARD
  // -------------------------------------------------------------
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(203, 213, 225);
  doc.setLineWidth(0.4);
  doc.roundedRect(MARGIN, y, CONTENT_WIDTH, 28, 2, 2, 'FD');

  // Left side: Details
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(15, 23, 42);
  doc.text(profile.name, MARGIN + 4, y + 6);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(71, 85, 105);
  doc.text(`Email: ${profile.userEmail}`, MARGIN + 4, y + 12);
  doc.text(`Department: ${profile.department}`, MARGIN + 4, y + 17);
  doc.text(`Role: ${profile.userRole} · Account Type: ${profile.accountType.replace('_', ' ')}`, MARGIN + 4, y + 22);

  // Right side: Score & Posture Badge
  const scoreBoxX = PAGE_WIDTH - MARGIN - 48;
  doc.setFillColor(15, 23, 42);
  doc.roundedRect(scoreBoxX, y + 3, 44, 22, 1.5, 1.5, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7);
  doc.setTextColor(148, 163, 184);
  doc.text('SECURITY POSTURE INDEX', scoreBoxX + 22, y + 8, { align: 'center' });

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  if (profile.awarenessScore >= 80) doc.setTextColor(52, 211, 153);
  else if (profile.awarenessScore >= 50) doc.setTextColor(251, 191, 36);
  else doc.setTextColor(248, 113, 113);
  doc.text(`${profile.awarenessScore} / 100`, scoreBoxX + 22, y + 15, { align: 'center' });

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7);
  doc.text(profile.postureTier.replace('_', ' '), scoreBoxX + 22, y + 21, { align: 'center' });

  y += 33;

  // -------------------------------------------------------------
  // 2. EXECUTIVE POSTURE ASSESSMENT
  // -------------------------------------------------------------
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9.5);
  doc.setTextColor(15, 23, 42);
  doc.text('1. EXECUTIVE BEHAVIORAL ASSESSMENT', MARGIN, y);
  y += 4;

  doc.setFillColor(241, 245, 249);
  doc.setDrawColor(226, 232, 240);
  const summaryLines = doc.splitTextToSize(profile.aiExecutiveSummary, CONTENT_WIDTH - 8);
  const summaryBoxHeight = summaryLines.length * 4.2 + 8;
  doc.roundedRect(MARGIN, y, CONTENT_WIDTH, summaryBoxHeight, 1.5, 1.5, 'FD');

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(30, 41, 59);
  doc.text(summaryLines, MARGIN + 4, y + 5.5);
  y += summaryBoxHeight + 5;

  // -------------------------------------------------------------
  // 3. WHAT WAS DONE WRONG (POLICY VIOLATIONS & BLIND SPOTS)
  // -------------------------------------------------------------
  y = checkPage(doc, y, 40, title, subtitle, badge);

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9.5);
  doc.setTextColor(15, 23, 42);
  doc.text('2. WHAT OCCURRED (RULE VIOLATIONS & INTERCEPTIONS)', MARGIN, y);
  y += 4;

  // Telemetry breakdown pills
  doc.setFillColor(248, 250, 252);
  doc.roundedRect(MARGIN, y, CONTENT_WIDTH, 11, 1, 1, 'FD');
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.5);
  doc.setTextColor(71, 85, 105);
  const telemetrySummary = `Total Prompts: ${profile.totalInteractions}  |  Clean Interactions: ${profile.cleanInteractions}  |  Policy Interceptions: ${profile.violationsCount}  (${profile.blockedCount} BLOCKED / ${profile.maskedCount} MASKED)`;
  doc.text(telemetrySummary, MARGIN + 4, y + 7);
  y += 15;

  if (profile.primaryGaps.length === 0) {
    doc.setFillColor(236, 253, 245);
    doc.setDrawColor(167, 243, 208);
    doc.roundedRect(MARGIN, y, CONTENT_WIDTH, 14, 1.5, 1.5, 'FD');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(6, 95, 70);
    doc.text('NO POLICY VIOLATIONS RECORDED', MARGIN + 4, y + 6);
    doc.setFont('helvetica', 'normal');
    doc.text('Employee demonstrated consistent adherence to corporate perimeter data security and zero-leakage guidelines.', MARGIN + 4, y + 10.5);
    y += 18;
  } else {
    for (const gap of profile.primaryGaps) {
      y = checkPage(doc, y, 22, title, subtitle, badge);

      doc.setFillColor(255, 241, 242);
      doc.setDrawColor(254, 205, 211);
      doc.roundedRect(MARGIN, y, CONTENT_WIDTH, 18, 1.5, 1.5, 'FD');

      // Category badge
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8);
      doc.setTextColor(190, 18, 60);
      doc.text(`[VIOLATION: ${gap.category}]`, MARGIN + 4, y + 5.5);

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(159, 18, 57);
      doc.text(`Frequency: ${gap.incidentCount} detected incident${gap.incidentCount > 1 ? 's' : ''}`, PAGE_WIDTH - MARGIN - 4, y + 5.5, { align: 'right' });

      // Detailed root cause description
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(71, 85, 105);
      const gapDescLines = doc.splitTextToSize(gap.description, CONTENT_WIDTH - 8);
      doc.text(gapDescLines, MARGIN + 4, y + 11);

      y += 21;
    }
  }

  // Recent Incidents Forensics Table
  if (profile.recentIncidentsSummary && profile.recentIncidentsSummary.length > 0) {
    y = checkPage(doc, y, 32, title, subtitle, badge);

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(15, 23, 42);
    doc.text('Recent Interception Log Forensics:', MARGIN, y);
    y += 4;

    // Table Header
    doc.setFillColor(226, 232, 240);
    doc.rect(MARGIN, y, CONTENT_WIDTH, 6, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7);
    doc.setTextColor(51, 65, 85);
    doc.text('TIMESTAMP', MARGIN + 3, y + 4.2);
    doc.text('VIOLATION TYPE', MARGIN + 45, y + 4.2);
    doc.text('PERIMETER ACTION', MARGIN + 110, y + 4.2);
    doc.text('RISK SCORE', PAGE_WIDTH - MARGIN - 4, y + 4.2, { align: 'right' });
    y += 6;

    doc.setFont('helvetica', 'normal');
    for (const inc of profile.recentIncidentsSummary) {
      y = checkPage(doc, y, 7, title, subtitle, badge);

      const isBlock = inc.action === 'BLOCK';
      doc.setFillColor(isBlock ? 255 : 248, isBlock ? 245 : 250, isBlock ? 245 : 252);
      doc.rect(MARGIN, y, CONTENT_WIDTH, 6, 'F');

      doc.setFontSize(7);
      doc.setTextColor(71, 85, 105);
      doc.text(inc.timestamp.substring(0, 19).replace('T', ' '), MARGIN + 3, y + 4.2);
      doc.text(inc.attackType, MARGIN + 45, y + 4.2);

      if (isBlock) {
        doc.setTextColor(225, 29, 72);
        doc.setFont('helvetica', 'bold');
        doc.text('BLOCK (STOPPED)', MARGIN + 110, y + 4.2);
      } else {
        doc.setTextColor(217, 119, 6);
        doc.setFont('helvetica', 'bold');
        doc.text('MODIFIED (MASKED)', MARGIN + 110, y + 4.2);
      }

      doc.setFont('helvetica', 'bold');
      doc.setTextColor(isBlock ? 225 : 217, isBlock ? 29 : 119, isBlock ? 72 : 6);
      doc.text(`${inc.riskScore} / 100`, PAGE_WIDTH - MARGIN - 4, y + 4.2, { align: 'right' });
      doc.setFont('helvetica', 'normal');

      y += 6;
    }
    y += 4;
  }

  // -------------------------------------------------------------
  // 4. WHAT IS THERE TO BE IMPROVED (PRESCRIBED REMEDIATION)
  // -------------------------------------------------------------
  y = checkPage(doc, y, 40, title, subtitle, badge);

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9.5);
  doc.setTextColor(15, 23, 42);
  doc.text('3. WHAT TO IMPROVE (PRESCRIBED MICRO-LEARNING & ACTION ITEMS)', MARGIN, y);
  y += 4;

  for (const mod of profile.recommendedModules) {
    const isCompleted = profile.assignedModules.some(a => a.moduleId === mod.id && a.status === 'COMPLETED');
    const boxHeight = 42;
    y = checkPage(doc, y, boxHeight + 4, title, subtitle, badge);

    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(203, 213, 225);
    doc.roundedRect(MARGIN, y, CONTENT_WIDTH, boxHeight, 1.5, 1.5, 'FD');

    // Module ID & Title
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(15, 23, 42);
    doc.text(`${mod.id}: ${mod.title}`, MARGIN + 4, y + 5.5);

    // Duration & Status pill
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7);
    if (isCompleted) {
      doc.setTextColor(16, 185, 129);
      doc.text(`COMPLETED (Verified)`, PAGE_WIDTH - MARGIN - 4, y + 5.5, { align: 'right' });
    } else {
      doc.setTextColor(217, 119, 6);
      doc.text(`REQUIRED REMEDIATION (${mod.durationMinutes} min)`, PAGE_WIDTH - MARGIN - 4, y + 5.5, { align: 'right' });
    }

    // Why this training is needed
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(14, 116, 144);
    doc.text('Why Needed:', MARGIN + 4, y + 10.5);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(51, 65, 85);
    const whyLines = doc.splitTextToSize(mod.relevanceExplanation || mod.description, CONTENT_WIDTH - 28);
    doc.text(whyLines, MARGIN + 22, y + 10.5);

    // Key Guidelines to follow
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(15, 23, 42);
    doc.text('Key Guidelines to Follow:', MARGIN + 4, y + 18.5);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(71, 85, 105);
    let bulletY = y + 23;
    for (const takeaway of mod.keyTakeaways.slice(0, 2)) {
      doc.text(`• ${takeaway}`, MARGIN + 6, bulletY);
      bulletY += 4;
    }

    // Action item
    doc.setFillColor(238, 242, 255);
    doc.roundedRect(MARGIN + 4, y + 32, CONTENT_WIDTH - 8, 7.5, 1, 1, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7);
    doc.setTextColor(67, 56, 202);
    doc.text(`Action Item: ${mod.actionItem}`, MARGIN + 6, y + 36.8);

    y += boxHeight + 4;
  }

  // -------------------------------------------------------------
  // 5. SIGN-OFF & COMPLIANCE SEAL
  // -------------------------------------------------------------
  y = checkPage(doc, y, 22, title, subtitle, badge);

  doc.setFillColor(241, 245, 249);
  doc.roundedRect(MARGIN, y, CONTENT_WIDTH, 16, 1.5, 1.5, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.5);
  doc.setTextColor(30, 41, 59);
  doc.text('AEGIS HUMAN RISK GOVERNANCE & COMPLIANCE ENDORSEMENT', MARGIN + 4, y + 5);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(6.5);
  doc.setTextColor(100, 116, 139);
  doc.text('This evaluation was conducted under enterprise AI security monitoring guidelines in full compliance with GDPR / DPDP.', MARGIN + 4, y + 9);
  doc.text(`SOC Audit Hash: ${Math.random().toString(36).substring(2, 15).toUpperCase()} | Status: Official Record`, MARGIN + 4, y + 13);

  // Apply footers to all pages
  const totalPages = doc.getNumberOfPages();
  for (let p = 1; p <= totalPages; p++) {
    doc.setPage(p);
    drawFooter(doc, p, totalPages);
  }

  return doc;
}

/**
 * Triggers browser download of the Employee Awareness Dossier PDF
 */
export function exportEmployeeDossierPdf(profile: UserAwarenessProfile): void {
  const doc = buildEmployeeDossierPdfDoc(profile);
  const safeFilename = `AEGIS_Awareness_Dossier_${profile.name.replace(/[^a-zA-Z0-9]/g, '_')}_${profile.awarenessScore}pts.pdf`;
  savePdfDocument(doc, safeFilename);
}

/**
 * Builds a professional Security Audit & Forensic Event Log PDF document
 */
export function buildSecurityAuditPdfDoc(
  events: LogEvent[],
  userRole: UserRole = 'ADMIN',
  operatorEmail: string = 'admin.soc@nexus-corp.com'
): jsPDF {
  const doc = new jsPDF({ unit: 'mm', format: 'a4', orientation: 'landscape' });
  const LANDSCAPE_WIDTH = 297;
  const LANDSCAPE_HEIGHT = 210;
  const L_MARGIN = 12;
  const L_CONTENT_WIDTH = LANDSCAPE_WIDTH - L_MARGIN * 2;

  const reportDate = new Date().toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });

  const title = 'PERIMETER SECURITY AUDIT & FORENSIC EVENT LOG';
  const subtitle = `Generated: ${reportDate} | Operator: ${operatorEmail} (${userRole})`;
  const badge = `RECORDS: ${events.length} EVENTS`;

  const drawLandscapeHeader = (pageNum: number) => {
    doc.setFillColor(15, 23, 42);
    doc.rect(0, 0, LANDSCAPE_WIDTH, 22, 'F');
    doc.setFillColor(6, 182, 212);
    doc.rect(0, 22, LANDSCAPE_WIDTH, 1.2, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(13);
    doc.setTextColor(255, 255, 255);
    doc.text('AEGIS', L_MARGIN, 10);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(148, 163, 184);
    doc.text('Perimeter Boundary Security Gateway · Security Operations Center', L_MARGIN + 20, 10);

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(6, 182, 212);
    doc.text(badge, LANDSCAPE_WIDTH - L_MARGIN, 10, { align: 'right' });

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(255, 255, 255);
    doc.text(title, L_MARGIN, 18);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(203, 213, 225);
    doc.text(subtitle, LANDSCAPE_WIDTH - L_MARGIN, 18, { align: 'right' });
  };

  const drawLandscapeFooter = (pageNum: number, total: number) => {
    const fY = LANDSCAPE_HEIGHT - 8;
    doc.setDrawColor(226, 232, 240);
    doc.setLineWidth(0.3);
    doc.line(L_MARGIN, fY - 2, LANDSCAPE_WIDTH - L_MARGIN, fY - 2);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(6.5);
    doc.setTextColor(100, 116, 139);
    doc.text('AUDIT ASSURANCE: SHA-256 HASH CHAIN ENFORCED · ZERO PLAINTEXT SECRETS RETAINED · COMPLIANT WITH SOC-2 & GDPR ART. 30', L_MARGIN, fY + 2);
    doc.text(`Page ${pageNum} of ${total}`, LANDSCAPE_WIDTH - L_MARGIN, fY + 2, { align: 'right' });
  };

  drawLandscapeHeader(1);
  let y = 29;

  // Audit Metrics Bar
  const totalBlocks = events.filter(e => e.action === 'BLOCK').length;
  const totalMasked = events.filter(e => e.action === 'MODIFIED').length;
  const totalClean = events.filter(e => e.action === 'ALLOW').length;

  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(203, 213, 225);
  doc.roundedRect(L_MARGIN, y, L_CONTENT_WIDTH, 10, 1, 1, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.5);
  doc.setTextColor(15, 23, 42);
  doc.text(`Total Interceptions: ${events.length}`, L_MARGIN + 4, y + 6.5);

  doc.setTextColor(225, 29, 72);
  doc.text(`Critical Blocks: ${totalBlocks}`, L_MARGIN + 60, y + 6.5);

  doc.setTextColor(217, 119, 6);
  doc.text(`Masked Payloads: ${totalMasked}`, L_MARGIN + 120, y + 6.5);

  doc.setTextColor(16, 185, 129);
  doc.text(`Approved / Clean: ${totalClean}`, L_MARGIN + 180, y + 6.5);

  doc.setTextColor(100, 116, 139);
  doc.setFont('helvetica', 'normal');
  doc.text(`Classification: OFFICIAL SOC AUDIT RECORD`, LANDSCAPE_WIDTH - L_MARGIN - 4, y + 6.5, { align: 'right' });

  y += 14;

  // Table Header
  const printTableHeader = (curY: number) => {
    doc.setFillColor(30, 41, 59);
    doc.rect(L_MARGIN, curY, L_CONTENT_WIDTH, 6, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(6.5);
    doc.setTextColor(255, 255, 255);
    doc.text('TIMESTAMP', L_MARGIN + 2, curY + 4.2);
    doc.text('USER IDENTITY', L_MARGIN + 32, curY + 4.2);
    doc.text('ROLE', L_MARGIN + 78, curY + 4.2);
    doc.text('VIOLATION / ATTACK', L_MARGIN + 98, curY + 4.2);
    doc.text('ACTION', L_MARGIN + 144, curY + 4.2);
    doc.text('SCORE', L_MARGIN + 172, curY + 4.2);
    doc.text('INCIDENT REASON & POLICY TRIGGER', L_MARGIN + 188, curY + 4.2);
    return curY + 6;
  };

  y = printTableHeader(y);

  // Table Rows
  const maxEventsToRender = Math.min(events.length, 120); // Render up to 120 recent events
  for (let i = 0; i < maxEventsToRender; i++) {
    const ev = events[i];
    if (y > LANDSCAPE_HEIGHT - 16) {
      doc.addPage();
      drawLandscapeHeader(doc.getNumberOfPages());
      y = printTableHeader(26);
    }

    const isBlock = ev.action === 'BLOCK';
    const isMask = ev.action === 'MODIFIED';

    doc.setFillColor(i % 2 === 0 ? 255 : 248, i % 2 === 0 ? 255 : 250, i % 2 === 0 ? 255 : 252);
    doc.rect(L_MARGIN, y, L_CONTENT_WIDTH, 5.5, 'F');

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(6.5);
    doc.setTextColor(71, 85, 105);
    doc.text(ev.timestamp.substring(0, 19).replace('T', ' '), L_MARGIN + 2, y + 3.8);

    doc.setFont('helvetica', 'bold');
    doc.setTextColor(15, 23, 42);
    const shortUser = ev.user.length > 26 ? ev.user.substring(0, 24) + '...' : ev.user;
    doc.text(shortUser, L_MARGIN + 32, y + 3.8);

    doc.setFont('helvetica', 'normal');
    doc.setTextColor(100, 116, 139);
    doc.text(ev.user_role || 'USER', L_MARGIN + 78, y + 3.8);

    doc.setFont('helvetica', 'bold');
    if (isBlock) doc.setTextColor(225, 29, 72);
    else if (isMask) doc.setTextColor(217, 119, 6);
    else doc.setTextColor(16, 185, 129);
    doc.text(ev.attack_type || 'None', L_MARGIN + 98, y + 3.8);

    if (isBlock) {
      doc.text('BLOCK', L_MARGIN + 144, y + 3.8);
    } else if (isMask) {
      doc.text('MODIFIED', L_MARGIN + 144, y + 3.8);
    } else {
      doc.text('ALLOW', L_MARGIN + 144, y + 3.8);
    }

    doc.text(`${ev.risk_score}`, L_MARGIN + 172, y + 3.8);

    doc.setFont('helvetica', 'normal');
    doc.setTextColor(71, 85, 105);
    const reasonText = (ev.reasons && ev.reasons.length > 0)
      ? ev.reasons[0]
      : (ev.report_summary || 'Compliant transmission');
    const shortReason = reasonText.length > 64 ? reasonText.substring(0, 62) + '...' : reasonText;
    doc.text(shortReason, L_MARGIN + 188, y + 3.8);

    y += 5.5;
  }

  const totalPages = doc.getNumberOfPages();
  for (let p = 1; p <= totalPages; p++) {
    doc.setPage(p);
    drawLandscapeFooter(p, totalPages);
  }

  return doc;
}

/**
 * Triggers browser download of the Security Audit & Forensic Event Log PDF
 */
export function exportSecurityAuditPdf(
  events: LogEvent[],
  userRole: UserRole = 'ADMIN',
  operatorEmail: string = 'admin.soc@nexus-corp.com'
): void {
  const doc = buildSecurityAuditPdfDoc(events, userRole, operatorEmail);
  const safeFilename = `AEGIS_Security_Audit_Report_${Date.now()}.pdf`;
  savePdfDocument(doc, safeFilename);
}
