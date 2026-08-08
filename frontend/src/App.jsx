import { useState } from "react";

// Point this at your FastAPI backend (uvicorn default port 8000)
const API_BASE_URL = "http://127.0.0.1:8000";

const CLASSIFICATION_COLORS = {
  safe: "#1e8e3e",
  suspicious: "#e8a33d",
  malicious: "#d93025",
};

const CLASSIFICATION_LABELS = {
  safe: "Safe ✅",
  suspicious: "Suspicious ⚠️",
  malicious: "Malicious ❌",
};

function App() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  async function handleScan(e) {
    e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch(`${API_BASE_URL}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url.trim() }),
      });

      if (!response.ok) {
        const errBody = await response.json().catch(() => ({}));
        throw new Error(errBody.detail || `Scan failed (status ${response.status})`);
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError(err.message || "Something went wrong while scanning.");
    } finally {
      setLoading(false);
    }
  }

  const color = result ? CLASSIFICATION_COLORS[result.classification] || "#666" : "#666";
  const label = result ? CLASSIFICATION_LABELS[result.classification] || result.classification : "";

  return (
    <div style={styles.page}>
      <div style={styles.container}>
        <h1 style={styles.title}>AI Website Threat Detection</h1>
        <p style={styles.subtitle}>
          Enter a website URL to check its SSL/TLS, domain, header, and DNS security.
        </p>

        <form onSubmit={handleScan} style={styles.form}>
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            style={styles.input}
          />
          <button type="submit" disabled={loading} style={styles.button}>
            {loading ? "Scanning..." : "Scan"}
          </button>
        </form>

        {error && <div style={styles.errorBox}>{error}</div>}

        {loading && <div style={styles.loadingBox}>Running SSL, WHOIS, DNS and header checks...</div>}

        {result && (
          <div style={styles.reportCard}>
            <div style={{ ...styles.badge, backgroundColor: color }}>{label}</div>

            <h2 style={styles.reportUrl}>{result.url}</h2>

            <div style={styles.scoreRow}>
              <span style={styles.scoreLabel}>Threat Score</span>
              <span style={{ ...styles.scoreValue, color }}>{result.threat_score}%</span>
            </div>

            <div style={styles.detailsGrid}>
              <div>
                <strong>TLS Version:</strong> {result.details?.tls_version || "N/A"}
              </div>
              <div>
                <strong>Domain Age (days):</strong> {result.details?.domain_age_days ?? "N/A"}
              </div>
              <div>
                <strong>Model Used:</strong> {result.model_used}
              </div>
              <div>
                <strong>Scan Time:</strong> {result.scan_duration_seconds}s
              </div>
            </div>

            <h3 style={styles.reasonsTitle}>Reasons</h3>
            <ul style={styles.reasonsList}>
              {result.reasons.map((reason, idx) => (
                <li key={idx} style={styles.reasonItem}>
                  {reason}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}

const styles = {
  page: {
    minHeight: "100vh",
    background: "#0f1117",
    color: "#e6e6e6",
    fontFamily: "system-ui, -apple-system, sans-serif",
    padding: "40px 20px",
  },
  container: {
    maxWidth: 640,
    margin: "0 auto",
  },
  title: {
    fontSize: 28,
    fontWeight: 700,
    marginBottom: 8,
  },
  subtitle: {
    color: "#9aa0a6",
    marginBottom: 24,
  },
  form: {
    display: "flex",
    gap: 10,
    marginBottom: 20,
  },
  input: {
    flex: 1,
    padding: "12px 14px",
    borderRadius: 8,
    border: "1px solid #2a2d34",
    background: "#1a1d24",
    color: "#e6e6e6",
    fontSize: 15,
  },
  button: {
    padding: "12px 20px",
    borderRadius: 8,
    border: "none",
    background: "#4f7cff",
    color: "#fff",
    fontWeight: 600,
    cursor: "pointer",
    fontSize: 15,
  },
  errorBox: {
    padding: 14,
    borderRadius: 8,
    background: "#3a1c1c",
    border: "1px solid #d93025",
    color: "#ff8a80",
    marginBottom: 20,
  },
  loadingBox: {
    padding: 14,
    borderRadius: 8,
    background: "#1a1d24",
    color: "#9aa0a6",
    marginBottom: 20,
  },
  reportCard: {
    background: "#1a1d24",
    border: "1px solid #2a2d34",
    borderRadius: 12,
    padding: 24,
  },
  badge: {
    display: "inline-block",
    padding: "6px 14px",
    borderRadius: 20,
    color: "#fff",
    fontWeight: 700,
    fontSize: 14,
    marginBottom: 12,
  },
  reportUrl: {
    fontSize: 18,
    wordBreak: "break-all",
    marginBottom: 16,
  },
  scoreRow: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    padding: "14px 0",
    borderTop: "1px solid #2a2d34",
    borderBottom: "1px solid #2a2d34",
    marginBottom: 16,
  },
  scoreLabel: {
    color: "#9aa0a6",
    fontSize: 14,
  },
  scoreValue: {
    fontSize: 26,
    fontWeight: 700,
  },
  detailsGrid: {
    display: "grid",
    gridTemplateColumns: "1fr 1fr",
    gap: 10,
    fontSize: 14,
    color: "#c4c7cc",
    marginBottom: 20,
  },
  reasonsTitle: {
    fontSize: 15,
    marginBottom: 10,
  },
  reasonsList: {
    margin: 0,
    paddingLeft: 20,
  },
  reasonItem: {
    marginBottom: 6,
    color: "#c4c7cc",
    fontSize: 14,
  },
};

export default App;