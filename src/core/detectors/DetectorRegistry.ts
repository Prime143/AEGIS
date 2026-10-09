import { Detector } from './Detector';
import { Finding, OrganizationContext, Severity } from '../types';
import { RegexDetector } from './RegexDetector';
import { DictionaryDetector } from './DictionaryDetector';
import { ContextualDetector } from './ContextualDetector';

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  CRITICAL: 100,
  HIGH: 75,
  MEDIUM: 50,
  LOW: 25,
  INFO: 10
};

export class DetectorRegistry {
  private detectors: Map<string, Detector> = new Map();

  constructor() {
    // Register standard deterministic detection layers
    this.register(new RegexDetector());
    this.register(new DictionaryDetector());
    this.register(new ContextualDetector());
  }

  register(detector: Detector): void {
    this.detectors.set(detector.id, detector);
  }

  unregister(detectorId: string): boolean {
    return this.detectors.delete(detectorId);
  }

  getDetectors(): Detector[] {
    return Array.from(this.detectors.values());
  }

  getDetector(id: string): Detector | undefined {
    return this.detectors.get(id);
  }

  async runAll(input: string, context?: OrganizationContext): Promise<Finding[]> {
    if (!input) return [];

    const allFindings: Finding[] = [];

    for (const detector of this.detectors.values()) {
      try {
        const findings = await detector.analyze(input, context);
        allFindings.push(...findings);
      } catch (err) {
        console.error(`Detector [${detector.id}] failure:`, err);
        // Fail-closed detector error finding if needed
      }
    }

    return this.deduplicateAndSort(allFindings);
  }

  /**
   * Sort findings by start span, and if overlapping, retain the one with higher severity/confidence.
   */
  private deduplicateAndSort(findings: Finding[]): Finding[] {
    if (findings.length <= 1) return findings;

    // Filter out findings without valid spans first
    const spanFindings = findings.filter(f => f.matchedSpan !== undefined);
    const nonSpanFindings = findings.filter(f => f.matchedSpan === undefined);

    // Sort by start position ascending, then length descending
    spanFindings.sort((a, b) => {
      const aSpan = a.matchedSpan!;
      const bSpan = b.matchedSpan!;
      if (aSpan.start !== bSpan.start) {
        return aSpan.start - bSpan.start;
      }
      return (bSpan.end - bSpan.start) - (aSpan.end - aSpan.start);
    });

    const resolved: Finding[] = [];

    for (const current of spanFindings) {
      const curSpan = current.matchedSpan!;
      let hasOverlap = false;

      for (let i = 0; i < resolved.length; i++) {
        const existing = resolved[i];
        const exSpan = existing.matchedSpan!;

        // Check if current overlaps with existing
        if (curSpan.start < exSpan.end && curSpan.end > exSpan.start) {
          hasOverlap = true;
          const curWeight = SEVERITY_WEIGHTS[current.severity] * current.confidence;
          const exWeight = SEVERITY_WEIGHTS[existing.severity] * existing.confidence;

          if (curWeight > exWeight) {
            resolved[i] = current; // Replace with higher priority finding
          }
          break;
        }
      }

      if (!hasOverlap) {
        resolved.push(current);
      }
    }

    return [...resolved, ...nonSpanFindings];
  }
}
