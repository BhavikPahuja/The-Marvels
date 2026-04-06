import './AuditBadge.css'

const riskIcons = {
  critical: 'gpp_bad',
  warning: 'warning',
  info: 'info',
  safe: 'verified_user',
}

const riskLabels = {
  critical: 'Critical Risk',
  warning: 'Warning',
  info: 'Information',
  safe: 'Safe',
}

export default function AuditBadge({ auditResult, loading }) {
  if (loading) {
    return (
      <div className="audit-badge audit-badge--loading">
        <div className="audit-badge__header">
          <span className="icon icon-sm" style={{ animation: 'spin 1s linear infinite' }}>sync</span>
          <span className="audit-badge__type">Analyzing secret...</span>
        </div>
        <div className="audit-badge__bar-track">
          <div className="audit-badge__bar-fill audit-badge__bar-fill--loading" />
        </div>
      </div>
    )
  }

  if (!auditResult) return null

  const { identified_type, risk_level, risk_score, recommendations, details } = auditResult

  return (
    <div className={`audit-badge audit-badge--${risk_level}`}>
      {/* Header row */}
      <div className="audit-badge__header">
        <span className={`icon audit-badge__icon audit-badge__icon--${risk_level}`}>
          {riskIcons[risk_level] || 'info'}
        </span>
        <div className="audit-badge__title-group">
          <span className="audit-badge__type">{identified_type}</span>
          <span className={`badge badge--${risk_level === 'critical' ? 'red' : risk_level === 'warning' ? 'yellow' : risk_level === 'safe' ? 'green' : 'blue'}`}>
            {riskLabels[risk_level]}
          </span>
        </div>
        <span className="audit-badge__score">{risk_score}</span>
      </div>

      {/* Risk bar */}
      <div className="audit-badge__bar-track">
        <div
          className={`audit-badge__bar-fill audit-badge__bar-fill--${risk_level}`}
          style={{ width: `${risk_score}%` }}
        />
      </div>

      {/* Recommendations */}
      {recommendations && recommendations.length > 0 && (
        <ul className="audit-badge__recs">
          {recommendations.map((rec, i) => (
            <li key={i}>
              <span className="icon icon-sm">chevron_right</span>
              {rec}
            </li>
          ))}
        </ul>
      )}

      {/* Details (collapsed) */}
      {details && Object.keys(details).length > 0 && (
        <div className="audit-badge__details">
          {Object.entries(details).map(([key, val]) => (
            <span key={key} className="audit-badge__detail-chip">
              {key}: <strong>{String(val)}</strong>
            </span>
          ))}
        </div>
      )}
    </div>
  )
}
