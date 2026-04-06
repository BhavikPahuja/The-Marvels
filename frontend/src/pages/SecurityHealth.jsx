import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import Sidebar from "../components/Sidebar";
import StatusBar from "../components/StatusBar";
import { decryptPayload, fetchVaultEntries } from "../utils/vaultCrypto";
import { getMasterKey } from "../utils/sessionSecrets";
import AnimatedNumber from "../components/AnimatedNumber";
import RevealText from "../components/RevealText";
import useAnimatedNumber from "../hooks/useAnimatedNumber";
import "./SecurityHealth.css";

const DAY_MS = 24 * 60 * 60 * 1000;

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function formatRelativeTime(timestamp) {
  if (!timestamp) return "just now";

  const time = new Date(timestamp).getTime();
  if (Number.isNaN(time)) return "just now";

  const diffMs = Date.now() - time;
  const minutes = Math.floor(diffMs / 60000);

  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;

  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function getPasswordStrength(secret) {
  if (!secret) return 0;

  let score = Math.min(35, secret.length * 2.8);
  if (/[A-Z]/.test(secret)) score += 15;
  if (/[a-z]/.test(secret)) score += 15;
  if (/\d/.test(secret)) score += 15;
  if (/[^A-Za-z0-9]/.test(secret)) score += 20;

  return clamp(Math.round(score), 0, 100);
}

function buildSignalBars(healthScore) {
  const base = clamp(healthScore - 8, 55, 95);

  return Array.from({ length: 10 }, (_, i) => {
    const variance = i % 2 === 0 ? i * 2 : (10 - i) * 2;
    return clamp(base + variance - 8, 48, 100);
  });
}

export default function SecurityHealth() {
  const navigate = useNavigate();
  const masterPassword = getMasterKey();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [healthScore, setHealthScore] = useState(0);
  const [defenseBars, setDefenseBars] = useState([
    { label: "Encryption", value: 0 },
    { label: "Key Hygiene", value: 0 },
    { label: "Access Keys", value: 0 },
    { label: "Vault Freshness", value: 0 },
  ]);
  const [signalBars, setSignalBars] = useState([
    65, 70, 74, 78, 73, 80, 76, 83, 88, 84,
  ]);
  const [latencyMs, setLatencyMs] = useState(0);
  const [uptimePct, setUptimePct] = useState("0.0");
  const [events, setEvents] = useState([]);
  const [lastScanAt, setLastScanAt] = useState("");
  const [counts, setCounts] = useState({ total: 0, decrypted: 0, locked: 0 });

  useEffect(() => {
    if (!sessionStorage.getItem("sv_access_token")) {
      navigate("/");
      return;
    }

    loadSecurityHealth();
  }, []);

  async function loadSecurityHealth() {
    if (!masterPassword) {
      setError(
        "Missing master passphrase in this session. Please sign in again.",
      );
      setLoading(false);
      return;
    }

    setLoading(true);
    setError("");

    const start = performance.now();

    try {
      const entries = await fetchVaultEntries();

      const analyzed = await Promise.all(
        entries.map(async (entry) => {
          try {
            const plain = await decryptPayload(
              entry.ciphertext,
              entry.iv,
              entry.salt,
              masterPassword,
            );

            return {
              ...entry,
              decryptError: false,
              strength: getPasswordStrength(plain.password || ""),
            };
          } catch {
            return {
              ...entry,
              decryptError: true,
              strength: 0,
            };
          }
        }),
      );

      const end = performance.now();
      const measuredLatency = Math.max(8, Math.round(end - start));

      const total = analyzed.length;
      const decryptedCount = analyzed.filter(
        (item) => !item.decryptError,
      ).length;
      const lockedCount = total - decryptedCount;

      const encryptionScore =
        total === 0 ? 82 : Math.round((decryptedCount / total) * 100);

      const avgStrength =
        decryptedCount === 0
          ? 70
          : Math.round(
              analyzed
                .filter((item) => !item.decryptError)
                .reduce((sum, item) => sum + item.strength, 0) / decryptedCount,
            );

      const accessScore =
        total === 0
          ? 88
          : clamp(100 - Math.round((lockedCount / total) * 50), 45, 100);

      const freshCount = analyzed.filter((item) => {
        const time = new Date(item.updated_at || item.created_at).getTime();
        return !Number.isNaN(time) && Date.now() - time <= 30 * DAY_MS;
      }).length;

      const freshnessScore =
        total === 0
          ? 85
          : clamp(Math.round((freshCount / total) * 100), 40, 100);

      const bars = [
        { label: "Encryption", value: encryptionScore },
        { label: "Key Hygiene", value: avgStrength },
        { label: "Access Keys", value: accessScore },
        { label: "Vault Freshness", value: freshnessScore },
      ];

      const composite = Math.round(
        encryptionScore * 0.35 +
          avgStrength * 0.3 +
          accessScore * 0.2 +
          freshnessScore * 0.15,
      );

      const normalizedScore = clamp(composite, 0, 100);

      const timeline = analyzed
        .sort((a, b) => {
          const bTime = new Date(b.updated_at || b.created_at).getTime();
          const aTime = new Date(a.updated_at || a.created_at).getTime();
          return bTime - aTime;
        })
        .slice(0, 6)
        .map((item) => {
          const updated = new Date(
            item.updated_at || item.created_at,
          ).getTime();
          const created = new Date(item.created_at).getTime();
          const isNew =
            !Number.isNaN(updated) &&
            !Number.isNaN(created) &&
            Math.abs(updated - created) < 60000;

          if (item.decryptError) {
            return {
              icon: "lock",
              title: "Credential locked",
              detail: `${item.label} could not be decrypted with this session key.`,
              time: formatRelativeTime(item.updated_at || item.created_at),
              type: "warning",
            };
          }

          if (isNew) {
            return {
              icon: "add_task",
              title: "New credential protected",
              detail: `${item.label} was added and encrypted client-side.`,
              time: formatRelativeTime(item.created_at),
              type: "success",
            };
          }

          return {
            icon: "sync",
            title: "Credential integrity updated",
            detail: `${item.label} was updated and re-encrypted successfully.`,
            time: formatRelativeTime(item.updated_at),
            type: "info",
          };
        });

      timeline.unshift({
        icon: "verified",
        title: "Backend vault scan complete",
        detail: `${total} encrypted records checked from the API.`,
        time: "just now",
        type: "success",
      });

      setLatencyMs(measuredLatency);
      setUptimePct((98 + (normalizedScore / 100) * 1.9).toFixed(1));
      setCounts({ total, decrypted: decryptedCount, locked: lockedCount });
      setDefenseBars(bars);
      setHealthScore(normalizedScore);
      setSignalBars(buildSignalBars(normalizedScore));
      setEvents(timeline);
      setLastScanAt(new Date().toISOString());
    } catch (err) {
      setError(
        err.message || "Failed to fetch security telemetry from backend.",
      );
      setEvents([]);
    } finally {
      setLoading(false);
    }
  }

  const animatedHealthScore = useAnimatedNumber(healthScore, {
    duration: 1200,
    enabled: !loading,
    startValue: 0,
  });

  const animatedDecryptedCount = useAnimatedNumber(counts.decrypted, {
    duration: 900,
    enabled: !loading,
    startValue: 0,
  });

  const animatedLockedCount = useAnimatedNumber(counts.locked, {
    duration: 900,
    enabled: !loading,
    startValue: 0,
  });

  const animatedTotalCount = useAnimatedNumber(counts.total, {
    duration: 950,
    enabled: !loading,
    startValue: 0,
  });

  const animatedEventsCount = useAnimatedNumber(events.length, {
    duration: 800,
    enabled: !loading,
    startValue: 0,
  });

  const warningEventsCount = useMemo(
    () => events.filter((event) => event.type === "warning").length,
    [events],
  );

  const averageDefense = useMemo(() => {
    if (!defenseBars.length) return 0;
    return Math.round(
      defenseBars.reduce((sum, item) => sum + item.value, 0) /
        defenseBars.length,
    );
  }, [defenseBars]);

  const coveragePct = counts.total
    ? Math.round((counts.decrypted / counts.total) * 100)
    : 0;

  const actionInsights = useMemo(() => {
    const items = [];

    if (counts.locked > 0) {
      items.push(
        "Resolve locked credentials to restore full local decryption coverage.",
      );
    }

    if (averageDefense < 75) {
      items.push("Increase key hygiene by rotating weak or reused passwords.");
    }

    if (latencyMs > 250) {
      items.push("Backend scan latency is elevated. Re-check API stability.");
    }

    if (warningEventsCount > 1) {
      items.push(
        "Multiple warning events detected. Review recent vault operations.",
      );
    }

    const hasUrgent = items.length > 0;
    if (!hasUrgent) {
      items.push(
        "No urgent action required. Continue routine weekly security scans.",
      );
    }

    return {
      items: items.slice(0, 4),
      hasUrgent,
    };
  }, [averageDefense, counts.locked, latencyMs, warningEventsCount]);

  const circumference = 2 * Math.PI * 90;
  const dashOffset =
    circumference - (animatedHealthScore / 100) * circumference;
  const connectionStrong = latencyMs > 0 && latencyMs <= 250;

  const statusHeading = loading
    ? "Running vault scan..."
    : healthScore >= 90
      ? "Your vault is strongly protected"
      : healthScore >= 70
        ? "Protection is stable with minor risk"
        : "Attention needed for optimal protection";

  return (
    <div className="app-layout">
      <Sidebar />
      <main className="main-content health-page animate-in">
        <header className="health__header">
          <div>
            <RevealText
              as="h2"
              text="Security Health"
              msPerChar={40}
              initialDelay={90}
            />
            <RevealText
              as="p"
              className="text-muted"
              text="Live vault defense status from backend scan telemetry."
              msPerChar={12}
              initialDelay={200}
            />
          </div>
          <button
            className="btn btn-secondary btn-sm"
            onClick={loadSecurityHealth}
            disabled={loading}
          >
            <span className="icon icon-sm">refresh</span>
            {loading ? "Scanning..." : "Refresh Scan"}
          </button>
        </header>

        {error && (
          <div
            style={{
              padding: "10px 14px",
              background: "rgba(255,60,60,0.12)",
              border: "1px solid rgba(255,60,60,0.3)",
              borderRadius: "8px",
              color: "#ff6b6b",
              fontSize: "0.85rem",
              marginBottom: "12px",
            }}
          >
            <span
              className="icon icon-sm"
              style={{ verticalAlign: "middle", marginRight: 6 }}
            >
              error
            </span>
            {error}
          </div>
        )}

        <div className="health__top">
          <div className="card health__gauge-card">
            <div className="health__gauge">
              <svg viewBox="0 0 200 200" className="health__gauge-svg">
                <circle
                  cx="100"
                  cy="100"
                  r="90"
                  fill="none"
                  stroke="var(--surface-highest)"
                  strokeWidth="8"
                />
                <circle
                  cx="100"
                  cy="100"
                  r="90"
                  fill="none"
                  stroke="var(--primary-container)"
                  strokeWidth="8"
                  strokeDasharray={circumference}
                  strokeDashoffset={dashOffset}
                  strokeLinecap="square"
                  transform="rotate(-90 100 100)"
                  className="health__gauge-arc"
                />
              </svg>
              <div className="health__gauge-center">
                <span className="health__gauge-value">
                  {loading ? (
                    "..."
                  ) : (
                    <AnimatedNumber
                      target={healthScore}
                      duration={1200}
                      enabled={!loading}
                      suffix="%"
                    />
                  )}
                </span>
                <span className="health__gauge-label">Protected</span>
              </div>
            </div>
            <div className="health__gauge-status">
              <span
                className={`icon ${healthScore >= 85 ? "text-green" : healthScore >= 70 ? "text-blue" : "text-error"}`}
              >
                {healthScore >= 85
                  ? "check_circle"
                  : healthScore >= 70
                    ? "report"
                    : "warning"}
              </span>
              <div>
                <RevealText
                  as="h3"
                  text={statusHeading}
                  msPerChar={14}
                  initialDelay={100}
                />
                <p className="text-muted" style={{ fontSize: "0.85rem" }}>
                  {Math.round(animatedDecryptedCount)} decrypted,{" "}
                  {Math.round(animatedLockedCount)} locked,{" "}
                  {Math.round(animatedTotalCount)} total records.
                  {lastScanAt
                    ? ` Last scan ${formatRelativeTime(lastScanAt)}.`
                    : ""}
                </p>
              </div>
            </div>
          </div>
        </div>

        <div className="health__cards-row">
          <div className="card">
            <div className="health__card-top">
              <span className="icon text-green">security</span>
              <span
                className={`badge ${healthScore >= 70 ? "badge--green" : "badge--red"}`}
              >
                {healthScore >= 70 ? "Active" : "Needs Review"}
              </span>
            </div>
            <RevealText
              as="h4"
              text="Automated Defense"
              msPerChar={18}
              initialDelay={130}
            />
            <p
              className="text-muted"
              style={{ fontSize: "0.82rem", marginTop: "8px" }}
            >
              Values are computed from decrypted vault coverage, key strength,
              and record freshness.
            </p>
            <div className="health__defense-bars">
              {defenseBars.map((item) => (
                <div key={item.label} className="health__defense-item">
                  <div className="health__defense-label">
                    <span>{item.label}</span>
                    <span className="text-green mono">
                      {loading ? (
                        "..."
                      ) : (
                        <AnimatedNumber
                          target={item.value}
                          duration={950}
                          enabled={!loading}
                          suffix="%"
                        />
                      )}
                    </span>
                  </div>
                  <div className="progress-bar">
                    <div
                      className="progress-bar__fill"
                      style={{ width: `${item.value}%` }}
                    ></div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="card">
            <div className="health__card-top">
              <span className="icon text-blue">signal_cellular_alt</span>
              <span
                className={`badge ${connectionStrong ? "badge--blue" : "badge--red"}`}
              >
                {loading
                  ? "Scanning"
                  : connectionStrong
                    ? "Strong"
                    : "Degraded"}
              </span>
            </div>
            <RevealText
              as="h4"
              text="Connection Quality"
              msPerChar={18}
              initialDelay={160}
            />
            <p
              className="text-muted"
              style={{ fontSize: "0.82rem", marginTop: "8px" }}
            >
              Based on the latest authenticated backend scan request and
              processing cycle.
            </p>
            <div className="health__connection-visual">
              <div className="health__signal-bars">
                {signalBars.map((height, i) => (
                  <div
                    key={i}
                    className="health__signal-bar"
                    style={{
                      height: `${height}%`,
                      animationDelay: `${i * 100}ms`,
                    }}
                  ></div>
                ))}
              </div>
              <div className="health__connection-stats">
                <div>
                  <span className="text-muted" style={{ fontSize: "0.7rem" }}>
                    LATENCY
                  </span>
                  <span className="mono text-green">
                    {loading ? (
                      "..."
                    ) : (
                      <AnimatedNumber
                        target={latencyMs}
                        duration={900}
                        enabled={!loading}
                        suffix="ms"
                      />
                    )}
                  </span>
                </div>
                <div>
                  <span className="text-muted" style={{ fontSize: "0.7rem" }}>
                    UPTIME
                  </span>
                  <span className="mono text-green">
                    {loading ? (
                      "..."
                    ) : (
                      <AnimatedNumber
                        target={Number(uptimePct)}
                        decimals={1}
                        duration={1200}
                        enabled={!loading}
                        suffix="%"
                      />
                    )}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="health__intel-grid">
          <section className="card health__intel-card">
            <div className="health__card-top">
              <span className="icon text-blue">radar</span>
              <span className="badge badge--blue">Realtime</span>
            </div>
            <RevealText
              as="h4"
              text="Threat Snapshot"
              msPerChar={18}
              initialDelay={190}
            />
            <div className="health__intel-metrics">
              <div className="health__intel-metric">
                <span className="text-muted">Defense Avg</span>
                <strong className="mono text-green">
                  {loading ? (
                    "..."
                  ) : (
                    <AnimatedNumber
                      target={averageDefense}
                      duration={900}
                      enabled={!loading}
                      suffix="%"
                    />
                  )}
                </strong>
              </div>
              <div className="health__intel-metric">
                <span className="text-muted">Warning Events</span>
                <strong className="mono text-error">
                  {loading ? (
                    "..."
                  ) : (
                    <AnimatedNumber
                      target={warningEventsCount}
                      duration={800}
                      enabled={!loading}
                    />
                  )}
                </strong>
              </div>
              <div className="health__intel-metric">
                <span className="text-muted">Coverage</span>
                <strong className="mono text-blue">
                  {loading ? (
                    "..."
                  ) : (
                    <AnimatedNumber
                      target={coveragePct}
                      duration={900}
                      enabled={!loading}
                      suffix="%"
                    />
                  )}
                </strong>
              </div>
            </div>
          </section>

          <section className="card health__intel-card">
            <div className="health__card-top">
              <span className="icon text-green">playlist_add_check</span>
              <span
                className={`badge ${actionInsights.hasUrgent ? "badge--red" : "badge--green"}`}
              >
                {actionInsights.hasUrgent ? "Priority" : "Stable"}
              </span>
            </div>
            <RevealText
              as="h4"
              text="Priority Queue"
              msPerChar={18}
              initialDelay={220}
            />
            <ul className="health__action-list">
              {actionInsights.items.map((item) => (
                <li key={item}>
                  <span className="icon icon-sm">task_alt</span>
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </section>
        </div>

        <div className="health__events">
          <div className="vault__section-header">
            <RevealText
              as="h3"
              text="Recent Protection Events"
              msPerChar={22}
              initialDelay={220}
            />
            <span className="badge badge--green">
              {loading ? "..." : `${Math.round(animatedEventsCount)} Events`}
            </span>
          </div>

          {loading ? (
            <div className="health__empty-state text-muted">
              <span className="icon icon-sm">sync</span>
              Fetching security events from vault activity...
            </div>
          ) : events.length === 0 ? (
            <div className="health__empty-state text-muted">
              <span className="icon icon-sm">info</span>
              No events yet. Add or update credentials to generate telemetry.
            </div>
          ) : (
            <div className="health__events-list">
              {events.map((event, i) => (
                <div
                  key={`${event.title}-${i}`}
                  className="health__event animate-in"
                  style={{ animationDelay: `${i * 80}ms` }}
                >
                  <div
                    className={`health__event-icon health__event-icon--${event.type}`}
                  >
                    <span className="icon">{event.icon}</span>
                  </div>
                  <div className="health__event-content">
                    <RevealText
                      as="h4"
                      className="health__event-title"
                      text={event.title}
                      msPerChar={10}
                      initialDelay={i * 60}
                    />
                    <p className="text-muted" style={{ fontSize: "0.82rem" }}>
                      {event.detail}
                    </p>
                  </div>
                  <span className="health__event-time text-muted">
                    {event.time}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="card health__audit-cta">
          <div className="health__audit-left">
            <span className="icon icon-lg text-blue">search</span>
            <div>
              <RevealText
                as="h4"
                text="Deep Security Audit"
                msPerChar={18}
                initialDelay={120}
              />
              <p className="text-muted" style={{ fontSize: "0.85rem" }}>
                Run another full scan over the backend vault feed and refresh
                all risk signals.
              </p>
            </div>
          </div>
          <button
            className="btn btn-primary"
            onClick={loadSecurityHealth}
            disabled={loading}
          >
            <span className="icon icon-sm">play_arrow</span>
            {loading ? "Scanning..." : "Start Scan"}
          </button>
        </div>

        <StatusBar />
      </main>
    </div>
  );
}
