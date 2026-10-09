import { GoogleGenAI } from '@google/genai';
import { AIProvider, AIProviderMetadata, ProviderRequest, ProviderResponse } from '../types';

export class GeminiProvider implements AIProvider {
  readonly id = 'provider-gemini';
  private apiKey: string | undefined;

  constructor() {
    this.apiKey = process.env.GEMINI_API_KEY;
  }

  private isConfigured(): boolean {
    return !!(this.apiKey && this.apiKey !== 'your_api_key_here' && this.apiKey.trim().length > 10);
  }

  metadata(): AIProviderMetadata {
    const configured = this.isConfigured();
    return {
      id: this.id,
      name: 'Google Gemini (External Provider)',
      type: 'external',
      model: 'gemini-2.5-flash',
      isAvailable: configured,
      description: 'External cloud AI provider integrated via official Google GenAI SDK with server-side proxy boundary.',
      environmentStatus: configured ? 'CONFIGURED' : 'NOT_CONFIGURED'
    };
  }

  async healthCheck(): Promise<{ status: 'HEALTHY' | 'DEGRADED' | 'UNAVAILABLE'; latencyMs: number; message?: string }> {
    if (!this.isConfigured()) {
      return {
        status: 'UNAVAILABLE',
        latencyMs: 0,
        message: 'GEMINI_API_KEY is not configured in environment variables. Gateway will route to Safe Mock Provider.'
      };
    }

    const start = performance.now();
    try {
      const ai = new GoogleGenAI({ apiKey: this.apiKey! });
      // Ping with lightweight health probe
      const res = await ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: [{ text: 'Health probe. Reply: OK' }]
      });
      const latencyMs = Math.round(performance.now() - start);
      return {
        status: res.text ? 'HEALTHY' : 'DEGRADED',
        latencyMs,
        message: 'Gemini Cloud API endpoint is reachable.'
      };
    } catch (e: any) {
      const latencyMs = Math.round(performance.now() - start);
      return {
        status: 'UNAVAILABLE',
        latencyMs,
        message: `Gemini connectivity failed: ${e.message || 'Unknown error'}`
      };
    }
  }

  async sendPrompt(request: ProviderRequest): Promise<ProviderResponse> {
    if (!this.isConfigured()) {
      throw new Error('GeminiProvider is not configured. Missing GEMINI_API_KEY.');
    }

    const start = performance.now();
    const ai = new GoogleGenAI({ apiKey: this.apiKey! });

    const contents: any[] = [];
    if (request.systemInstruction) {
      contents.push({ text: `System Instruction: ${request.systemInstruction}\n\nUser: ${request.prompt}` });
    } else {
      contents.push({ text: request.prompt });
    }

    const response = await ai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents
    });

    const latencyMs = Math.round(performance.now() - start);
    const content = response.text || '';

    return {
      content,
      providerId: this.id,
      model: 'gemini-2.5-flash',
      latencyMs,
      tokenUsage: {
        promptTokens: Math.round(request.prompt.length / 4),
        completionTokens: Math.round(content.length / 4),
        totalTokens: Math.round((request.prompt.length + content.length) / 4)
      }
    };
  }
}
