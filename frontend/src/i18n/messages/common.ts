import { defineMessages } from './define'

export const commonMessages = defineMessages({
  'app.name': {
    defaultMessage: 'Airlock',
    description: 'Product name shown in the Airlock user interface.',
  },
  'common.locale.unsupportedBuild': {
    defaultMessage: 'The saved interface language is unavailable in this build. The interface is using English so an administrator can choose a supported language.',
    description: 'Recovery warning shown when the persisted system locale is not compiled into this frontend distribution.',
  },
})
