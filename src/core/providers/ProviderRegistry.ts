import { AIProvider, AIProviderMetadata } from '../types';
import { SafeMockProvider } from './SafeMockProvider';
import { GeminiProvider } from './GeminiProvider';

export class ProviderRegistry {
  private providers: Map<string, AIProvider> = new Map();
  private activeProviderId: string;

  constructor() {
    const mock = new SafeMockProvider();
    const gemini = new GeminiProvider();

    this.register(mock);
    this.register(gemini);

    // Auto-select Gemini if configured, otherwise SafeMock
    if (gemini.metadata().isAvailable) {
      this.activeProviderId = gemini.id;
    } else {
      this.activeProviderId = mock.id;
    }
  }

  register(provider: AIProvider): void {
    this.providers.set(provider.id, provider);
  }

  getProviders(): AIProviderMetadata[] {
    return Array.from(this.providers.values()).map(p => p.metadata());
  }

  getProvider(id: string): AIProvider | undefined {
    return this.providers.get(id);
  }

  getActiveProviderId(): string {
    return this.activeProviderId;
  }

  setActiveProvider(id: string): boolean {
    if (this.providers.has(id)) {
      this.activeProviderId = id;
      return true;
    }
    return false;
  }

  getActiveProvider(): AIProvider {
    const candidate = this.providers.get(this.activeProviderId);
    if (candidate && candidate.metadata().isAvailable) {
      return candidate;
    }
    // Fallback to safe mock provider if candidate unavailable
    return this.providers.get('provider-safe-mock')!;
  }
}
