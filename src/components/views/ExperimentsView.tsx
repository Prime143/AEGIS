import React, { useState } from 'react';
import { 
  FlaskConical, 
  Play, 
  RefreshCw, 
  CheckCircle, 
  AlertTriangle, 
  Database, 
  Clock, 
  BarChart3,
  Layers,
  Info
} from 'lucide-react';
import { BenchmarkMetrics, ExperimentDatasetRecord } from '../../core/types';

interface ExperimentsViewProps {
  authToken?: string;
  userRole?: string;
}

export const ExperimentsView: React.FC<ExperimentsViewProps> = ({
  authToken = 'AEGIS_SECURE_TOKEN_2026',
  userRole
}) => {
  const [activeSplit, setActiveSplit] = useState<'TRAIN' | 'DEV' | 'TEST'>('TEST');
  const [metrics, setMetrics] = useState<BenchmarkMetrics[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  const [datasetRecords, setDatasetRecords] = useState<ExperimentDatasetRecord[]>([]);
  const [activeTab, setActiveTab] = useState<'benchmarks' | 'dataset'>('benchmarks');

  const getHeaders = () => ({
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${authToken}`
  });

  const runEvaluation = async () => {
    setIsRunning(true);
    try {
      const res = await fetch('/api/experiments/evaluate', {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({ split: activeSplit })
      });
      if (res.ok) {
        const data = await res.json();
        setMetrics(data);
      }
    } catch (e) {
      console.error('Benchmark execution error:', e);
    } finally {
      setIsRunning(false);
    }
  };

  const loadDataset = async () => {
    try {
      const res = await fetch('/api/experiments/dataset', {
        headers: { 'Authorization': `Bearer ${authToken}` }
      });
      if (res.ok) {
        const data = await res.json();
        setDatasetRecords(data);
      }
    } catch (e) {
      console.error('Failed to load dataset:', e);
    }
  };

  React.useEffect(() => {
    loadDataset();
    runEvaluation(); // Initial benchmark run
  }, [activeSplit]);

  const filteredDataset = datasetRecords.filter(d => d.split === activeSplit);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 p-4 rounded-xl bg-slate-900/60 border border-slate-800">
        <div>
          <h2 className="text-base font-bold text-slate-100 font-mono flex items-center space-x-2">
            <FlaskConical className="w-4 h-4 text-cyan-400" />
            <span>DETECTOR BENCHMARK EVALUATION &amp; DATASET METRICS</span>
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Empirical measurements on partitioned datasets (Train / Dev / Test). Zero fabricated statistics.
          </p>
        </div>

        <div className="flex items-center space-x-2 font-mono text-xs">
          <select
            value={activeSplit}
            onChange={(e) => setActiveSplit(e.target.value as any)}
            className="p-2 rounded bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none cursor-pointer"
          >
            <option value="TEST">Dataset Split: TEST (Held-Out)</option>
            <option value="DEV">Dataset Split: DEV (Validation)</option>
            <option value="TRAIN">Dataset Split: TRAIN</option>
          </select>

          <button
            onClick={runEvaluation}
            disabled={isRunning}
            className="flex items-center space-x-1.5 px-3 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-slate-950 font-bold transition-all cursor-pointer shadow-[0_0_10px_rgba(6,182,212,0.2)]"
          >
            <Play className={`w-3.5 h-3.5 ${isRunning ? 'animate-spin' : ''}`} />
            <span>{isRunning ? 'EVALUATING...' : 'EXECUTE BENCHMARK'}</span>
          </button>
        </div>
      </div>

      {/* Sub Tabs */}
      <div className="flex space-x-2 border-b border-slate-800 font-mono text-xs pb-2">
        <button
          onClick={() => setActiveTab('benchmarks')}
          className={`px-3 py-1.5 rounded-lg transition-colors ${
            activeTab === 'benchmarks' ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30' : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Measured Benchmark Results
        </button>
        <button
          onClick={() => setActiveTab('dataset')}
          className={`px-3 py-1.5 rounded-lg transition-colors ${
            activeTab === 'dataset' ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30' : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          Evaluation Dataset Records ({filteredDataset.length})
        </button>
      </div>

      {/* Benchmarks Tab */}
      {activeTab === 'benchmarks' && (
        <div className="space-y-4 font-mono text-xs">
          {metrics.length === 0 ? (
            <div className="p-8 text-center text-slate-500 rounded-xl bg-slate-900/60 border border-slate-800">
              Executing benchmark on {activeSplit} split...
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {metrics.map((m, idx) => (
                <div key={idx} className="p-5 rounded-xl bg-slate-900/70 border border-slate-800 space-y-4">
                  <div className="flex justify-between items-start">
                    <div>
                      <span className="text-[10px] text-cyan-400 font-semibold uppercase">{m.datasetSplit} SPLIT</span>
                      <h3 className="text-sm font-bold text-slate-100 mt-1">{m.detectorName}</h3>
                    </div>
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-300 border border-slate-700">
                      N = {m.totalEvaluated}
                    </span>
                  </div>

                  {/* Primary Metrics: Precision, Recall, F1 */}
                  <div className="grid grid-cols-3 gap-2 text-center p-3 rounded-lg bg-slate-950 border border-slate-800">
                    <div>
                      <div className="text-[10px] text-slate-400">PRECISION</div>
                      <div className="text-base font-bold text-cyan-300 mt-0.5">
                        {(m.precision * 100).toFixed(1)}%
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] text-slate-400">RECALL</div>
                      <div className="text-base font-bold text-emerald-400 mt-0.5">
                        {(m.recall * 100).toFixed(1)}%
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] text-slate-400">F1 SCORE</div>
                      <div className="text-base font-bold text-indigo-300 mt-0.5">
                        {(m.f1Score * 100).toFixed(1)}%
                      </div>
                    </div>
                  </div>

                  {/* Confusion Matrix Breakdown */}
                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                    <div className="text-[10px] text-slate-400 uppercase font-semibold">Confusion Matrix</div>
                    <div className="grid grid-cols-2 gap-2 text-[11px]">
                      <div className="p-2 rounded bg-slate-900 border border-slate-800/80">
                        <span className="text-slate-400">True Positives (TP): </span>
                        <span className="font-bold text-emerald-400">{m.truePositives}</span>
                      </div>
                      <div className="p-2 rounded bg-slate-900 border border-slate-800/80">
                        <span className="text-slate-400">False Positives (FP): </span>
                        <span className="font-bold text-amber-400">{m.falsePositives}</span>
                      </div>
                      <div className="p-2 rounded bg-slate-900 border border-slate-800/80">
                        <span className="text-slate-400">True Negatives (TN): </span>
                        <span className="font-bold text-emerald-400">{m.trueNegatives}</span>
                      </div>
                      <div className="p-2 rounded bg-slate-900 border border-slate-800/80">
                        <span className="text-slate-400">False Negatives (FN): </span>
                        <span className="font-bold text-rose-400">{m.falseNegatives}</span>
                      </div>
                    </div>
                  </div>

                  {/* Measured Latency */}
                  <div className="flex justify-between items-center text-[11px] text-slate-400 pt-1">
                    <span>Average Execution Latency:</span>
                    <span className="text-slate-200 font-semibold">{m.averageLatencyMs} ms / prompt</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Dataset Records Tab */}
      {activeTab === 'dataset' && (
        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 font-mono text-xs space-y-3">
          <div className="flex justify-between items-center">
            <span className="font-bold text-slate-200">
              Evaluation Records ({activeSplit} Split)
            </span>
            <span className="text-[10px] text-slate-500">
              Strictly segregated to prevent evaluation leakage
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-slate-800 text-[11px] text-slate-400">
                  <th className="pb-2 font-medium">RECORD ID</th>
                  <th className="pb-2 font-medium">GROUND TRUTH</th>
                  <th className="pb-2 font-medium">CATEGORY</th>
                  <th className="pb-2 font-medium">PROMPT SNIPPET</th>
                  <th className="pb-2 font-medium">TEMPLATE FAMILY</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredDataset.map((rec) => (
                  <tr key={rec.id} className="hover:bg-slate-800/40">
                    <td className="py-2.5 text-cyan-400 font-semibold">{rec.id}</td>
                    <td className="py-2.5">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        rec.label === 'SENSITIVE'
                          ? 'bg-rose-950 text-rose-300 border-rose-800'
                          : 'bg-emerald-950 text-emerald-300 border-emerald-800'
                      }`}>
                        {rec.label}
                      </span>
                    </td>
                    <td className="py-2.5 text-slate-300">{rec.category}</td>
                    <td className="py-2.5 text-slate-400 max-w-[320px] truncate">{rec.prompt}</td>
                    <td className="py-2.5 text-slate-500 text-[11px]">{rec.templateFamily}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
