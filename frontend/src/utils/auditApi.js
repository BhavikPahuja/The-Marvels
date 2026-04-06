/**
 * auditApi.js — Ephemeral Secret Audit Client
 *
 * Sends a secret to POST /api/audit/ for heuristic analysis.
 * The server never saves the string — analysis is in-memory only.
 */

const API_BASE = 'http://localhost:8000/api'

/**
 * Audit a secret string via the Django heuristic engine.
 * Requires JWT authentication.
 *
 * @param {string} secret - The raw string to audit
 * @returns {Promise<Object>} Risk profile { identified_type, risk_level, risk_score, recommendations, details }
 */
export async function auditSecret(secret) {
  const token = sessionStorage.getItem('sv_access_token')

  const res = await fetch(`${API_BASE}/audit/`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ secret }),
  })

  if (!res.ok) {
    throw new Error('Audit failed')
  }

  return res.json()
}
