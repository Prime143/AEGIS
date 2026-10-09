import { Finding, DetectionCategory } from '../types';

export interface MaskingTransformation {
  originalSpan: { start: number; end: number };
  originalLength: number;
  replacement: string;
  category: DetectionCategory;
}

export interface MaskingResult {
  sanitizedText: string;
  transformationsCount: number;
  transformations: MaskingTransformation[];
}

export class MaskingService {
  private static readonly CATEGORY_PLACEHOLDERS: Record<DetectionCategory, string> = {
    CREDENTIAL: '[REDACTED_SECRET]',
    PII: '[REDACTED_PII]',
    INTERNAL_IDENTIFIER: '[REDACTED_INTERNAL_ID]',
    CONFIDENTIAL_TECHNICAL: '[REDACTED_CONFIDENTIAL_TECH]',
    CONFIDENTIAL_FINANCIAL: '[REDACTED_FINANCIAL]',
    APPSEC_EXPLOIT: '[EXPLOIT_PAYLOAD_BLOCKED]',
    PROMPT_INJECTION: '[PROMPT_INJECTION_REMOVED]',
    INSIDER_THREAT: '[UNAUTHORIZED_REQUEST_REDACTED]',
    BENIGN: ''
  };

  /**
   * Applies non-destructive masking to input text based on findings.
   * Replaces spans in reverse order (highest index to lowest) to maintain valid character offsets.
   */
  mask(input: string, findings: Finding[]): MaskingResult {
    if (!input || !findings || findings.length === 0) {
      return {
        sanitizedText: input || '',
        transformationsCount: 0,
        transformations: []
      };
    }

    // Filter findings that recommend MASK or BLOCK (when sanitizing partial) with valid spans
    const maskableFindings = findings
      .filter(f => f.matchedSpan !== undefined && f.matchedSpan.start >= 0 && f.matchedSpan.end <= input.length)
      .sort((a, b) => b.matchedSpan!.start - a.matchedSpan!.start); // Reverse sort by start index

    let result = input;
    const transformations: MaskingTransformation[] = [];

    // Avoid duplicate replacements for identical or overlapping spans
    const processedSpans: Array<{ start: number; end: number }> = [];

    for (const finding of maskableFindings) {
      const span = finding.matchedSpan!;
      
      // Check if this span was already replaced or intersects a processed span
      const overlaps = processedSpans.some(p => span.start < p.end && span.end > p.start);
      if (overlaps) continue;

      const placeholder = span.maskedReplacement || 
        MaskingService.CATEGORY_PLACEHOLDERS[finding.category] || 
        '[REDACTED_SENSITIVE_DATA]';

      const before = result.substring(0, span.start);
      const after = result.substring(span.end);

      result = before + placeholder + after;

      transformations.push({
        originalSpan: { start: span.start, end: span.end },
        originalLength: span.end - span.start,
        replacement: placeholder,
        category: finding.category
      });

      processedSpans.push({ start: span.start, end: span.end });
    }

    return {
      sanitizedText: result,
      transformationsCount: transformations.length,
      transformations
    };
  }
}
