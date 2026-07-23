import { describe, expect, it } from 'vitest'
import { matchingWebSlashCommands } from './slashCommands'

describe('web slash command suggestions', () => {
  it('lists web context commands after a slash', () => {
    expect(matchingWebSlashCommands('/').map(command => command.name)).toEqual(['clear', 'compact'])
  })

  it('filters commands case-insensitively', () => {
    expect(matchingWebSlashCommands('/COM').map(command => command.name)).toEqual(['compact'])
  })

  it('closes suggestions after arguments or regular text', () => {
    expect(matchingWebSlashCommands('/compact now')).toEqual([])
    expect(matchingWebSlashCommands('compact')).toEqual([])
  })
})
