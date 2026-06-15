// Password strength scoring, kept in lockstep with the backend. The backend
// rejects anything below MIN_PASSWORD_SCORE using the same zxcvbn algorithm
// (Go: trustelem/zxcvbn), so a password the meter shows as acceptable is one
// the backend will accept.
import { ZxcvbnFactory } from '@zxcvbn-ts/core'
import * as zxcvbnCommon from '@zxcvbn-ts/language-common'

const zxcvbnFactory = new ZxcvbnFactory({
  dictionary: { ...zxcvbnCommon.dictionary },
  graphs: zxcvbnCommon.adjacencyGraphs,
})

// MIN_PASSWORD_SCORE mirrors auth.MinPasswordScore on the backend (0–4 scale).
export const MIN_PASSWORD_SCORE = 3

export interface Strength {
  score: number // 0..4
  ok: boolean // score >= MIN_PASSWORD_SCORE
  label: string
  warning: string
  suggestions: string[]
}

const LABELS = ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong']

// scorePassword returns a strength summary. userInputs (email, display name)
// count against the score when the password contains them.
export function scorePassword(password: string, userInputs: string[] = []): Strength {
  if (!password) {
    return { score: 0, ok: false, label: '', warning: '', suggestions: [] }
  }
  const r = zxcvbnFactory.check(password, userInputs)
  return {
    score: r.score,
    ok: r.score >= MIN_PASSWORD_SCORE,
    label: LABELS[r.score] ?? '',
    warning: r.feedback.warning ?? '',
    suggestions: r.feedback.suggestions ?? [],
  }
}
