import { Finding, OrganizationContext } from '../types';

export interface Detector {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly version: string;
  readonly isDeterministic: boolean;
  
  analyze(input: string, context?: OrganizationContext): Promise<Finding[]> | Finding[];
}
