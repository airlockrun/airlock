import { describe, expect, it } from 'vitest'
import { airlockCloneCommand, airlockInitCommand, airlockInstallCommand } from './airCommands'

describe('Air CLI commands', () => {
  it('installs the versioned global launcher', () => {
    expect(airlockInstallCommand('github.com/airlockrun/agentsdk/cmd/airlock', '0.4.0-rc.35')).toBe(
      'go install github.com/airlockrun/agentsdk/cmd/airlock@v0.4.0-rc.35',
    )
  })

  it('initializes through the global launcher', () => {
    expect(airlockInitCommand('my-app', 'https://airlock.example.com')).toBe(
      'airlock init my-app --url https://airlock.example.com',
    )
  })

  it('keeps the clone destination as the final positional argument', () => {
    const command = airlockCloneCommand('source-app', 'my-app', 'https://airlock.example.com')
    expect(command).toBe('airlock clone source-app --url https://airlock.example.com my-app')
    expect(command).not.toContain('go run')
  })
})
