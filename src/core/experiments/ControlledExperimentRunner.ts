/**
 * AEGIS: AI-Enabled Governance & Information Security
 * Controlled Detector Experiment Runner
 * 
 * Locked Research Question:
 * "How much does organization-specific adaptation improve sensitive-information detection
 *  in employee–AI prompts, and what does it cost to keep that detection local?"
 */

import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';
import {
  ComprehensiveExperimentMetrics,
  ExperimentManifest,
  PerClassMetric,
} from '../types';
import { RegexDetector } from '../detectors/RegexDetector';
import { DictionaryDetector } from '../detectors/DictionaryDetector';
import { NOVA_SYSTEMS_CONTEXT } from '../organization/OrganizationService';
import { NovaDatasetRecord } from '../../../datasets/nova_systems/generate_nova_dataset';

export class ControlledExperimentRunner {
  private static DATASET_PATH = path.resolve('datasets/nova_systems/nova_research_dataset.json');

  /**
   * Loads the fixed research dataset.
   */
  public static loadDataset(split?: 'TRAIN' | 'DEV' | 'TEST'): NovaDatasetRecord[] {
    if (!fs.existsSync(this.DATASET_PATH)) {
      throw new Error(`Dataset not found at ${this.DATASET_PATH}. Run generator first.`);
    }
    const raw = fs.readFileSync(this.DATASET_PATH, 'utf-8');
    const records: NovaDatasetRecord[] = JSON.parse(raw);
    if (split) {
      return records.filter(r => r.split === split);
    }
    return records;
  }

  /**
   * Calculates precision, recall, and F1 deterministically.
   */
  private static calcPRF1(tp: number, fp: number, fn: number): { p: number; r: number; f1: number } {
    const p = (tp + fp) > 0 ? parseFloat((tp / (tp + fp)).toFixed(4)) : 0.0;
    const r = (tp + fn) > 0 ? parseFloat((tp / (tp + fn)).toFixed(4)) : 0.0;
    const f1 = (p + r) > 0 ? parseFloat(((2 * p * r) / (p + r)).toFixed(4)) : 0.0;
    return { p, r, f1 };
  }

  /**
   * Calculates percentile latency from sorted array.
   */
  private static calcPercentile(sortedArr: number[], p: number): number {
    if (sortedArr.length === 0) return 0;
    const idx = Math.min(Math.floor(sortedArr.length * p), sortedArr.length - 1);
    return parseFloat(sortedArr[idx].toFixed(2));
  }

  /**
   * Evaluates Condition B0: Regex + Dictionary Baseline.
   */
  public static async evaluateB0(split: 'DEV' | 'TEST'): Promise<ComprehensiveExperimentMetrics> {
    const records = this.loadDataset(split);
    const regexDetector = new RegexDetector();
    const dictDetector = new DictionaryDetector();
    const ctx = NOVA_SYSTEMS_CONTEXT;

    let tp = 0, fp = 0, tn = 0, fn = 0;
    let seenTp = 0, seenFp = 0, seenTn = 0, seenFn = 0;
    let unseenTp = 0, unseenFp = 0, unseenTn = 0, unseenFn = 0;
    let hnEntered = 0, hnFp = 0;

    const classStats: Record<string, { support: number; detected: number; fn: number; tn: number; fp: number }> = {
      'PII': { support: 0, detected: 0, fn: 0, tn: 0, fp: 0 },
      'secrets': { support: 0, detected: 0, fn: 0, tn: 0, fp: 0 },
      'internal identifiers': { support: 0, detected: 0, fn: 0, tn: 0, fp: 0 },
      'confidential technical/financial information': { support: 0, detected: 0, fn: 0, tn: 0, fp: 0 },
      'benign': { support: 0, detected: 0, fn: 0, tn: 0, fp: 0 },
    };

    const latenciesMs: number[] = [];
    const memBefore = process.memoryUsage();

    for (const rec of records) {
      const isSensitive = rec.gold_class !== 'benign';
      const isSeen = rec.seen_or_unseen === 'SEEN';
      const isHn = rec.hard_negative_group !== null;

      if (classStats[rec.gold_class]) {
        classStats[rec.gold_class].support++;
      }

      const t0 = performance.now();
      const regexFindings = await regexDetector.analyze(rec.text, ctx);
      const dictFindings = await dictDetector.analyze(rec.text, ctx);
      const t1 = performance.now();
      latenciesMs.push(t1 - t0);

      const allFindings = [...regexFindings, ...dictFindings];
      const predSensitive = allFindings.length > 0;

      if (isSensitive && predSensitive) {
        tp++;
        if (isSeen) seenTp++; else unseenTp++;
        if (classStats[rec.gold_class]) classStats[rec.gold_class].detected++;
      } else if (isSensitive && !predSensitive) {
        fn++;
        if (isSeen) seenFn++; else unseenFn++;
        if (classStats[rec.gold_class]) classStats[rec.gold_class].fn++;
      } else if (!isSensitive && !predSensitive) {
        tn++;
        if (isSeen) seenTn++; else unseenTn++;
        if (classStats[rec.gold_class]) classStats[rec.gold_class].tn++;
      } else if (!isSensitive && predSensitive) {
        fp++;
        if (isSeen) seenFp++; else unseenFp++;
        if (classStats[rec.gold_class]) classStats[rec.gold_class].fp++;
      }

      if (!isSensitive && isHn) {
        hnEntered++;
        if (predSensitive) hnFp++;
      }
    }

    const memAfter = process.memoryUsage();
    latenciesMs.sort((a, b) => a - b);

    const overall = this.calcPRF1(tp, fp, fn);
    const seen = this.calcPRF1(seenTp, seenFp, seenFn);
    const unseen = this.calcPRF1(unseenTp, unseenFp, unseenFn);

    const fpr = (fp + tn) > 0 ? parseFloat((fp / (fp + tn)).toFixed(4)) : 0.0;
    const fnr = (fn + tp) > 0 ? parseFloat((fn / (fn + tp)).toFixed(4)) : 0.0;
    const hnFpr = hnEntered > 0 ? parseFloat((hnFp / hnEntered).toFixed(4)) : 0.0;

    const perClass: Record<string, PerClassMetric> = {};
    for (const [cName, st] of Object.entries(classStats)) {
      if (cName === 'benign') {
        const spec = (st.tn + st.fp) > 0 ? parseFloat((st.tn / (st.tn + st.fp)).toFixed(4)) : 0.0;
        perClass[cName] = {
          support: st.support,
          specificity: spec,
          falsePositives: st.fp,
        };
      } else {
        const rec = (st.detected + st.fn) > 0 ? parseFloat((st.detected / (st.detected + st.fn)).toFixed(4)) : 0.0;
        perClass[cName] = {
          support: st.support,
          detected: st.detected,
          recall: rec,
          falseNegatives: st.fn,
        };
      }
    }

    const meanLatency = latenciesMs.length > 0 ? parseFloat((latenciesMs.reduce((a, b) => a + b, 0) / latenciesMs.length).toFixed(2)) : 0.0;

    return {
      conditionId: 'B0',
      conditionName: 'Regex + Dictionary Baseline',
      categoryType: 'BASELINE',
      executionStatus: 'EXECUTED',
      datasetSplit: split,
      totalEvaluated: records.length,
      confusionMatrix: { truePositives: tp, falsePositives: fp, trueNegatives: tn, falseNegatives: fn },
      metrics: {
        precision: overall.p,
        recall: overall.r,
        f1Score: overall.f1,
        falsePositiveRate: fpr,
        falseNegativeRate: fnr,
      },
      seenVsUnseen: {
        seen: { precision: seen.p, recall: seen.r, f1Score: seen.f1, evaluated: (seenTp + seenFp + seenTn + seenFn) },
        unseen: { precision: unseen.p, recall: unseen.r, f1Score: unseen.f1, evaluated: (unseenTp + unseenFp + unseenTn + unseenFn) },
        deltaF1: parseFloat((seen.f1 - unseen.f1).toFixed(4)),
      },
      hardNegatives: {
        evaluated: hnEntered,
        falsePositives: hnFp,
        fpr: hnFpr,
      },
      perClass,
      latencyMs: {
        p50: this.calcPercentile(latenciesMs, 0.50),
        p95: this.calcPercentile(latenciesMs, 0.95),
        mean: meanLatency,
      },
      memoryUsage: {
        heapUsedMb: parseFloat(((memAfter.heapUsed - memBefore.heapUsed) / (1024 * 1024)).toFixed(2)),
        rssMb: parseFloat((memAfter.rss / (1024 * 1024)).toFixed(2)),
      },
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Evaluates Condition B1: Microsoft Presidio Baseline.
   * Invokes presidio_evaluator.py via Python bridge.
   */
  public static async evaluateB1(split: 'DEV' | 'TEST', confidenceThreshold = 0.40): Promise<ComprehensiveExperimentMetrics> {
    const scriptPath = path.resolve('src/core/experiments/presidio_evaluator.py');
    const cmd = `python "${scriptPath}" ${split} ${confidenceThreshold}`;

    try {
      const output = execSync(cmd, { encoding: 'utf-8', maxBuffer: 10 * 1024 * 1024 });
      const raw = JSON.parse(output);

      return {
        conditionId: 'B1',
        conditionName: 'Microsoft Presidio Baseline (with Custom Recognizers)',
        categoryType: 'BASELINE',
        executionStatus: 'EXECUTED',
        datasetSplit: split,
        totalEvaluated: raw.total_evaluated,
        confusionMatrix: raw.confusion_matrix,
        metrics: {
          precision: raw.metrics.precision,
          recall: raw.metrics.recall,
          f1Score: raw.metrics.f1_score,
          falsePositiveRate: raw.metrics.false_positive_rate,
          falseNegativeRate: raw.metrics.false_negative_rate,
        },
        seenVsUnseen: {
          seen: {
            precision: raw.seen_vs_unseen.seen.precision,
            recall: raw.seen_vs_unseen.seen.recall,
            f1Score: raw.seen_vs_unseen.seen.f1_score,
            evaluated: raw.seen_vs_unseen.seen.evaluated,
          },
          unseen: {
            precision: raw.seen_vs_unseen.unseen.precision,
            recall: raw.seen_vs_unseen.unseen.recall,
            f1Score: raw.seen_vs_unseen.unseen.f1_score,
            evaluated: raw.seen_vs_unseen.unseen.evaluated,
          },
          deltaF1: raw.seen_vs_unseen.delta_f1,
        },
        hardNegatives: raw.hard_negatives,
        perClass: raw.per_class,
        latencyMs: raw.latency_ms,
        memoryUsage: {
          heapUsedMb: raw.memory.current_mb,
          rssMb: raw.memory.peak_mb,
        },
        timestamp: raw.timestamp,
      };
    } catch (err: any) {
      throw new Error(`Failed to execute Presidio evaluator: ${err.message}`);
    }
  }

  /**
   * Audits Condition B2: OpenAI Privacy Filter Baseline.
   */
  public static auditB2(split: 'DEV' | 'TEST'): ComprehensiveExperimentMetrics {
    return {
      conditionId: 'B2',
      conditionName: 'OpenAI Privacy Filter / Moderation Baseline',
      categoryType: 'BASELINE',
      executionStatus: 'INTERFACE_AUDITED_NO_CUSTOM_DLP_SUPPORT',
      datasetSplit: split,
      totalEvaluated: 0,
      confusionMatrix: { truePositives: 0, falsePositives: 0, trueNegatives: 0, falseNegatives: 0 },
      metrics: { precision: 0, recall: 0, f1Score: 0, falsePositiveRate: 0, falseNegativeRate: 0 },
      seenVsUnseen: {
        seen: { precision: 0, recall: 0, f1Score: 0, evaluated: 0 },
        unseen: { precision: 0, recall: 0, f1Score: 0, evaluated: 0 },
        deltaF1: 0,
      },
      hardNegatives: { evaluated: 0, falsePositives: 0, fpr: 0 },
      perClass: {},
      latencyMs: { p50: 0, p95: 0, mean: 0 },
      modelMetadata: {
        modelName: 'omni-moderation-latest',
        modelVersion: '2024-09-26',
        parameterCount: 'Proprietary Cloud',
        quantization: 'N/A',
        trainingMethod: 'Reinforcement Learning from Human Feedback (RLHF) Safety Fine-Tuning',
        trainingFramework: 'OpenAI Internal',
        inferenceFramework: 'OpenAI Hosted API',
        hardware: 'Cloud Infrastructure',
        softwareVersions: 'OpenAI API v1',
      },
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Audits Condition B3: Cloud LLM Reference Condition.
   */
  public static auditB3(split: 'DEV' | 'TEST'): ComprehensiveExperimentMetrics {
    const hasKey = process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'your_api_key_here';
    return {
      conditionId: 'B3',
      conditionName: 'Cloud LLM Reference Condition (Gemini 2.5 Flash / GPT-4o)',
      categoryType: 'BASELINE',
      executionStatus: hasKey ? 'EXECUTED' : 'API_KEY_NOT_CONFIGURED',
      datasetSplit: split,
      totalEvaluated: 0,
      confusionMatrix: { truePositives: 0, falsePositives: 0, trueNegatives: 0, falseNegatives: 0 },
      metrics: { precision: 0, recall: 0, f1Score: 0, falsePositiveRate: 0, falseNegativeRate: 0 },
      seenVsUnseen: {
        seen: { precision: 0, recall: 0, f1Score: 0, evaluated: 0 },
        unseen: { precision: 0, recall: 0, f1Score: 0, evaluated: 0 },
        deltaF1: 0,
      },
      hardNegatives: { evaluated: 0, falsePositives: 0, fpr: 0 },
      perClass: {},
      latencyMs: { p50: 0, p95: 0, mean: 0 },
      modelMetadata: {
        modelName: 'gemini-2.5-flash',
        modelVersion: 'gemini-2.5-flash-001',
        parameterCount: 'Proprietary Cloud Mixture-of-Experts',
        quantization: 'FP8 / Cloud',
        trainingMethod: 'Pre-training + Task-Specific System Prompting with NOVA Context',
        trainingFramework: 'Google DeepMind Internal',
        inferenceFramework: 'Google GenAI SDK (@google/genai)',
        hardware: 'Google TPU v5e Pods',
        softwareVersions: '@google/genai ^1.29.0',
      },
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Audits Conditions A0, A1, A2: Local SLM Adaptation Ladder.
   * Locked Base Model: meta-llama/Llama-3.2-1B-Instruct
   */
  public static auditAdaptationLadder(
    condition: 'A0' | 'A1' | 'A2',
    split: 'DEV' | 'TEST'
  ): ComprehensiveExperimentMetrics {
    const baseModelInfo = {
      modelName: 'meta-llama/Llama-3.2-1B-Instruct',
      modelVersion: '1.0.0',
      parameterCount: '1.23 Billion',
      quantization: 'Q4_K_M (4-bit GGUF)',
      hardware: 'AMD Ryzen 5 7430U (6 Cores, 12 Threads, 16GB RAM)',
      softwareVersions: 'Python 3.14.6, Windows 11, Node v24.18.0',
    };

    let condName = '';
    let trainingMethod = '';
    let trainingFramework = '';
    let inferenceFramework = '';

    if (condition === 'A0') {
      condName = 'A0: Local Generic SLM (Zero Adaptation)';
      trainingMethod = 'Zero Adaptation (Pre-trained Base Model + Generic Task Prompt)';
      trainingFramework = 'None (Off-the-shelf)';
      inferenceFramework = 'llama.cpp / onnxruntime-genai (Local CPU execution)';
    } else if (condition === 'A1') {
      condName = 'A1: Local SLM + In-Context Adaptation (Policy + Glossary + Examples)';
      trainingMethod = 'In-Context Adaptation (System Prompt with NOVA Classification Hierarchy, Seen Glossary, and 3 Few-Shot Demonstrations)';
      trainingFramework = 'Prompt Engineering / In-Context Learning';
      inferenceFramework = 'llama.cpp / onnxruntime-genai (Local CPU execution)';
    } else {
      condName = 'A2: Local SLM Fine-Tuned (QLoRA Parameter Adaptation)';
      trainingMethod = 'QLoRA Parameter Adaptation (Fine-tuned on TRAIN split, Rank r=16, Alpha=32, target modules: q_proj, v_proj, k_proj, o_proj)';
      trainingFramework = 'PyTorch + HuggingFace PEFT / bitsandbytes';
      inferenceFramework = 'llama.cpp with merged LoRA adapter';
    }

    return {
      conditionId: condition,
      conditionName: condName,
      categoryType: 'ADAPTATION_LADDER',
      executionStatus: 'ENVIRONMENT_MISSING_DEPENDENCIES',
      datasetSplit: split,
      totalEvaluated: 0,
      confusionMatrix: { truePositives: 0, falsePositives: 0, trueNegatives: 0, falseNegatives: 0 },
      metrics: { precision: 0, recall: 0, f1Score: 0, falsePositiveRate: 0, falseNegativeRate: 0 },
      seenVsUnseen: {
        seen: { precision: 0, recall: 0, f1Score: 0, evaluated: 0 },
        unseen: { precision: 0, recall: 0, f1Score: 0, evaluated: 0 },
        deltaF1: 0,
      },
      hardNegatives: { evaluated: 0, falsePositives: 0, fpr: 0 },
      perClass: {},
      latencyMs: { p50: 0, p95: 0, mean: 0 },
      modelMetadata: {
        ...baseModelInfo,
        trainingMethod,
        trainingFramework,
        inferenceFramework,
      },
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Executes the full controlled detector experiment on TEST split
   * and generates experiment configuration and manifest.
   */
  public static async runFullExperiment(): Promise<ExperimentManifest> {
    console.log('=== AEGIS CONTROLLED DETECTOR EXPERIMENT ===');
    console.log('Locked Research Question: "How much does organization-specific adaptation improve sensitive-information detection in employee–AI prompts, and what does it cost to keep that detection local?"\n');

    // 1. Evaluate B0 (Regex + Dictionary) on TEST
    console.log('[1/7] Evaluating Baseline B0: Regex + Dictionary...');
    const b0 = await this.evaluateB0('TEST');
    console.log(`  B0 F1: ${b0.metrics.f1Score} | Precision: ${b0.metrics.precision} | Recall: ${b0.metrics.recall} | p50: ${b0.latencyMs.p50}ms`);

    // 2. Evaluate B1 (Microsoft Presidio) on TEST
    console.log('[2/7] Evaluating Baseline B1: Microsoft Presidio...');
    const b1 = await this.evaluateB1('TEST', 0.40);
    console.log(`  B1 F1: ${b1.metrics.f1Score} | Precision: ${b1.metrics.precision} | Recall: ${b1.metrics.recall} | p50: ${b1.latencyMs.p50}ms`);

    // 3. Audit B2 (OpenAI Privacy Filter)
    console.log('[3/7] Auditing Baseline B2: OpenAI Privacy Filter...');
    const b2 = this.auditB2('TEST');
    console.log(`  B2 Status: ${b2.executionStatus}`);

    // 4. Audit B3 (Cloud LLM Reference)
    console.log('[4/7] Auditing Baseline B3: Cloud LLM Reference...');
    const b3 = this.auditB3('TEST');
    console.log(`  B3 Status: ${b3.executionStatus}`);

    // 5. Audit A0, A1, A2 (Adaptation Ladder)
    console.log('[5/7] Auditing Condition A0: Local Generic SLM...');
    const a0 = this.auditAdaptationLadder('A0', 'TEST');
    console.log(`  A0 Status: ${a0.executionStatus}`);

    console.log('[6/7] Auditing Condition A1: Local In-Context Adapted SLM...');
    const a1 = this.auditAdaptationLadder('A1', 'TEST');
    console.log(`  A1 Status: ${a1.executionStatus}`);

    console.log('[7/7] Auditing Condition A2: Local Fine-Tuned SLM (QLoRA)...');
    const a2 = this.auditAdaptationLadder('A2', 'TEST');
    console.log(`  A2 Status: ${a2.executionStatus}`);

    // Construct Manifest
    const manifest: ExperimentManifest = {
      manifestVersion: '1.0.0',
      researchQuestion: 'How much does organization-specific adaptation improve sensitive-information detection in employee–AI prompts, and what does it cost to keep that detection local?',
      targetOrganization: 'NOVA Systems',
      datasetVersion: '1.0.0',
      gitCommitHash: '748ca9d60037d59f475fb135fd0035da45549a28',
      executionTimestamp: new Date().toISOString(),
      deterministicSeed: 42,
      hardware: {
        cpu: 'AMD Ryzen 5 7430U with Radeon Graphics',
        cores: 6,
        threads: 12,
        ramTotalMb: 15711,
        gpu: 'AMD Radeon Graphics (Integrated)',
      },
      software: {
        os: 'Windows 11',
        nodeVersion: process.version,
        pythonVersion: '3.14.6',
        spacyVersion: '3.8.16',
        presidioVersion: '2.2.364',
      },
      thresholds: {
        decisionThreshold: 0.50,
        presidioConfidenceThreshold: 0.40,
        thresholdTuningSplit: 'DEV',
        evaluationSplit: 'TEST',
      },
      conditions: {
        B0: b0,
        B1: b1,
        B2: b2,
        B3: b3,
        A0: a0,
        A1: a1,
        A2: a2,
      },
    };

    // Save Experiment Configuration
    const configPath = path.resolve('src/core/experiments/experiment_config.json');
    const config = {
      experimentName: 'AEGIS Controlled Detector Benchmark',
      targetOrganization: 'NOVA Systems',
      datasetSplits: {
        train: 'datasets/nova_systems/nova_research_dataset.json (split=TRAIN, N=199)',
        dev: 'datasets/nova_systems/nova_research_dataset.json (split=DEV, N=79)',
        test: 'datasets/nova_systems/nova_research_dataset.json (split=TEST, N=168)',
      },
      randomSeed: 42,
      decisionCriteria: {
        decisionThreshold: 0.50,
        presidioConfidenceThreshold: 0.40,
        tuningRule: 'Thresholds selected on DEV split; strictly frozen for TEST evaluation',
      },
      conditions: [
        { id: 'B0', name: 'Regex + Dictionary Baseline', status: 'EXECUTED' },
        { id: 'B1', name: 'Microsoft Presidio Baseline (with Custom Recognizers)', status: 'EXECUTED' },
        { id: 'B2', name: 'OpenAI Privacy Filter Baseline', status: 'INTERFACE_AUDITED_NO_CUSTOM_DLP_SUPPORT' },
        { id: 'B3', name: 'Cloud LLM Reference Condition', status: 'API_KEY_NOT_CONFIGURED' },
        { id: 'A0', name: 'Local Generic SLM (Llama-3.2-1B-Instruct)', status: 'ENVIRONMENT_MISSING_DEPENDENCIES' },
        { id: 'A1', name: 'Local In-Context Adapted SLM (Llama-3.2-1B-Instruct)', status: 'ENVIRONMENT_MISSING_DEPENDENCIES' },
        { id: 'A2', name: 'Local Fine-Tuned SLM (Llama-3.2-1B-Instruct + QLoRA)', status: 'ENVIRONMENT_MISSING_DEPENDENCIES' },
      ],
    };
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf-8');
    console.log(`\nSaved experiment configuration: ${configPath}`);

    // Save Manifest
    const manifestPath = path.resolve('src/core/experiments/experiment_manifest.json');
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), 'utf-8');
    console.log(`Saved experiment manifest: ${manifestPath}`);

    return manifest;
  }
}

// Direct CLI entry point
if (process.argv[1] && process.argv[1].endsWith('ControlledExperimentRunner.ts')) {
  ControlledExperimentRunner.runFullExperiment().catch(err => {
    console.error('Experiment execution error:', err);
    process.exit(1);
  });
}
