import { AIProvider, AIProviderMetadata, ProviderRequest, ProviderResponse } from '../types';

export class SafeMockProvider implements AIProvider {
  readonly id = 'provider-safe-mock';

  metadata(): AIProviderMetadata {
    return {
      id: this.id,
      name: 'AEGIS Safe Mock Provider (Simulated)',
      type: 'mock',
      model: 'aegis-deterministic-simulator-v1',
      isAvailable: true,
      description: 'Built-in deterministic mock provider for zero-dependency offline testing, air-gapped evaluation, and safe demonstrations.',
      environmentStatus: 'SIMULATED'
    };
  }

  async healthCheck(): Promise<{ status: 'HEALTHY' | 'DEGRADED' | 'UNAVAILABLE'; latencyMs: number; message?: string }> {
    const start = performance.now();
    await new Promise(r => setTimeout(r, 8)); // Simulate micro-delay
    const latencyMs = Math.round(performance.now() - start);
    return {
      status: 'HEALTHY',
      latencyMs,
      message: 'Mock provider operational in local memory.'
    };
  }

  async sendPrompt(request: ProviderRequest): Promise<ProviderResponse> {
    const start = performance.now();
    const prompt = request.prompt.trim();

    // Deterministic, realistic responses based on query domain
    let responseText = '';
    const lower = prompt.toLowerCase();

    if (lower.includes('react') || lower.includes('performance') || lower.includes('optimization')) {
      responseText = `Here are best practices for React performance optimization:
1. Use React.memo() for pure components that re-render often with unchanged props.
2. Memoize expensive computations with useMemo() and stable callbacks with useCallback().
3. Virtualize long lists with windowing libraries (e.g. react-window or tanstack-virtual).
4. Code-split routes and heavy components using React.lazy() and Suspense.
5. Avoid anonymous objects or functions declared in JSX render bodies.`;
    } else if (lower.includes('email') || lower.includes('welcome') || lower.includes('formal letter')) {
      responseText = `Subject: Welcome to the Team - Onboarding & Resources

Dear Colleague,

Welcome aboard! We are thrilled to have you join our team. Your onboarding portal and documentation are ready for your review. Please let us know if you need assistance configuring your local workstation or accessing internal services.

Best regards,
Organizational Operations Team`;
    } else if (lower.includes('summarize') || lower.includes('schema') || lower.includes('analyze')) {
      responseText = `Analysis Summary:
The provided text contains structured operational requests. The request structure has been inspected and adheres to corporate policy guidelines. All sanitized placeholder values have been preserved in context.`;
    } else if (lower.includes('sql') || lower.includes('database') || lower.includes('query')) {
      responseText = `To optimize relational database queries:
1. Ensure proper indexes exist on foreign keys and frequently filtered WHERE columns.
2. Avoid SELECT *; project only needed columns.
3. Use parameterized queries or prepared statements to prevent injection and enable query plan caching.
4. Inspect execution plans (EXPLAIN ANALYZE) to identify table scans.`;
    } else {
      responseText = `I have received your sanitized request through the AEGIS Security Gateway:
"${prompt.length > 80 ? prompt.substring(0, 80) + '...' : prompt}"

The request was safely processed. As an AI assistant governed by enterprise security policy, I am ready to assist with further tasks within corporate compliance boundaries.`;
    }

    const latencyMs = Math.round(performance.now() - start + 12);
    const words = responseText.split(/\s+/).length;

    return {
      content: responseText,
      providerId: this.id,
      model: 'aegis-deterministic-simulator-v1',
      latencyMs,
      tokenUsage: {
        promptTokens: Math.round(prompt.length / 4),
        completionTokens: words,
        totalTokens: Math.round(prompt.length / 4) + words
      }
    };
  }
}
