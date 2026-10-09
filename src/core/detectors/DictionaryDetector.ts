import { Detector } from './Detector';
import { Finding, OrganizationContext, DetectionCategory, Severity, SecurityAction } from '../types';

export class DictionaryDetector implements Detector {
  readonly id = 'detector-dictionary';
  readonly name = 'Organization Glossary & Entity Detector';
  readonly description = 'Matches input against organizational glossary terms, confidential codenames, and custom enterprise security rules.';
  readonly version = '1.8.0';
  readonly isDeterministic = true;

  analyze(input: string, context?: OrganizationContext): Finding[] {
    if (!input || typeof input !== 'string') return [];

    const findings: Finding[] = [];
    const lowerInput = input.toLowerCase();

    // 1. Process custom sensitive entities defined in organization context
    if (context?.sensitiveEntities) {
      for (const entity of context.sensitiveEntities) {
        if (entity.type === 'keyword') {
          const keyword = entity.pattern.toLowerCase();
          let pos = 0;
          while ((pos = lowerInput.indexOf(keyword, pos)) !== -1) {
            const start = pos;
            const end = pos + keyword.length;
            const rawMatched = input.substring(start, end);

            findings.push({
              id: `dict-ent-${entity.id}-${start}`,
              category: 'INTERNAL_IDENTIFIER',
              severity: entity.action === 'BLOCK' ? 'CRITICAL' : 'HIGH',
              confidence: 0.99,
              detector: this.name,
              matchedSpan: {
                start,
                end,
                text: rawMatched,
                maskedReplacement: entity.placeholder || '[REDACTED_INTERNAL_ENTITY]'
              },
              policyClass: `POL-ORG-${entity.id}`,
              recommendedAction: entity.action,
              explanation: entity.explanation || `Matched protected organizational entity: ${entity.name}`
            });

            pos += keyword.length;
          }
        } else if (entity.type === 'regex') {
          try {
            const regex = new RegExp(entity.pattern, 'gi');
            let match: RegExpExecArray | null;
            while ((match = regex.exec(input)) !== null) {
              const start = match.index;
              const end = start + match[0].length;

              findings.push({
                id: `dict-ent-${entity.id}-${start}`,
                category: 'CONFIDENTIAL_TECHNICAL',
                severity: entity.action === 'BLOCK' ? 'CRITICAL' : 'HIGH',
                confidence: 0.98,
                detector: this.name,
                matchedSpan: {
                  start,
                  end,
                  text: match[0],
                  maskedReplacement: entity.placeholder || '[REDACTED_CUSTOM_RULE]'
                },
                policyClass: `POL-ORG-${entity.id}`,
                recommendedAction: entity.action,
                explanation: entity.explanation || `Matched custom organization pattern: ${entity.name}`
              });
            }
          } catch (e) {
            console.error(`Invalid regex pattern in entity rule ${entity.name}:`, e);
          }
        }
      }
    }

    // 2. Process organization glossary terms
    if (context?.glossary) {
      for (const item of context.glossary) {
        const termLower = item.term.toLowerCase();
        let pos = 0;
        while ((pos = lowerInput.indexOf(termLower, pos)) !== -1) {
          const start = pos;
          const end = pos + termLower.length;
          const rawMatched = input.substring(start, end);

          let severity: Severity = 'MEDIUM';
          let action: SecurityAction = 'MASK';

          if (item.classification === 'RESTRICTED') {
            severity = 'CRITICAL';
            action = 'BLOCK';
          } else if (item.classification === 'CONFIDENTIAL') {
            severity = 'HIGH';
            action = 'MASK';
          }

          findings.push({
            id: `dict-glossary-${item.id}-${start}`,
            category: item.category || 'CONFIDENTIAL_TECHNICAL',
            severity,
            confidence: 0.95,
            detector: this.name,
            matchedSpan: {
              start,
              end,
              text: rawMatched,
              maskedReplacement: item.placeholder || `[REDACTED_${item.classification}]`
            },
            policyClass: `POL-GLOSSARY-${item.id}`,
            recommendedAction: action,
            explanation: `Protected organizational glossary term (${item.classification}): "${item.term}"`
          });

          pos += termLower.length;
        }
      }
    }

    return findings;
  }
}
