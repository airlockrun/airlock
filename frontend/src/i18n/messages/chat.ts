import { defineMessages } from './define'

export const chatMessages = defineMessages({
  'chat.systemAgent.status.running': {
    defaultMessage: 'Running',
    description: 'Status label for a system-agent run that is executing.',
  },
  'chat.systemAgent.status.suspended': {
    defaultMessage: 'Suspended',
    description: 'Status label for a system-agent run waiting to resume.',
  },
  'chat.systemAgent.status.complete': {
    defaultMessage: 'Complete',
    description: 'Status label for a completed system-agent run.',
  },
  'chat.systemAgent.status.error': {
    defaultMessage: 'Error',
    description: 'Status label for a failed system-agent run.',
  },
  'chat.systemAgent.status.cancelled': {
    defaultMessage: 'Cancelled',
    description: 'Status label for a cancelled system-agent run.',
  },
  'chat.systemAgent.trigger.prompt': {
    defaultMessage: 'Chat',
    description: 'Trigger label for a system-agent run started from operator chat.',
  },
  'chat.systemAgent.trigger.bridge': {
    defaultMessage: 'Bridge',
    description: 'Trigger label for a system-agent run started through a messaging bridge.',
  },
  'chat.systemAgent.trigger.event': {
    defaultMessage: 'Event',
    description: 'Trigger label for a system-agent run started by a system event.',
  },
  'chat.action.approve': {
    defaultMessage: 'Approve',
    description: 'Button that approves a pending chat tool action.',
  },
  'chat.action.cancel': {
    defaultMessage: 'Cancel',
    description: 'Button that cancels the currently running chat response.',
  },
  'chat.action.reject': {
    defaultMessage: 'Reject',
    description: 'Button that rejects a pending chat tool action.',
  },
  'chat.action.start': {
    defaultMessage: 'Start',
    description: 'Button that starts a stopped app from its chat composer.',
  },
  'chat.agent.commandsAriaLabel': {
    defaultMessage: 'Chat commands',
    description: 'Accessible label for the slash-command suggestion list in app chat.',
  },
  'chat.agent.emptyExistingPrefix': {
    defaultMessage: 'Conversation with',
    description: 'Prefix before an app name in the empty state of an existing app conversation.',
  },
  'chat.agent.emptyHint': {
    defaultMessage: "Send a message to begin - it's saved as a new conversation once you do.",
    description: 'Instruction shown in an empty app conversation.',
  },
  'chat.agent.emptyNewPrefix': {
    defaultMessage: 'New conversation with',
    description: 'Prefix before an app name in the empty state of a new app conversation.',
  },
  'chat.agent.loadingEarlier': {
    defaultMessage: 'Loading earlier messages…',
    description: 'Status shown while older app chat messages are loading.',
  },
  'chat.agent.loadingNewer': {
    defaultMessage: 'Loading newer messages…',
    description: 'Status shown while newer app chat messages are loading.',
  },
  'chat.agent.messagePlaceholder': {
    defaultMessage: 'Type a message...',
    description: 'Placeholder in the app chat message composer.',
  },
  'chat.agent.newMessages': {
    defaultMessage: 'New messages - click to jump to latest',
    description: 'Banner that returns an app chat scrolled into history to its latest messages.',
  },
  'chat.agent.stoppedMessage': {
    defaultMessage: 'This app is stopped. Start it to chat.',
    description: 'Explanation shown above the composer when an app is stopped.',
  },
  'chat.agent.stoppedPlaceholder': {
    defaultMessage: 'App is stopped',
    description: 'Disabled composer placeholder shown when an app is stopped.',
  },
  'chat.agent.thisApp': {
    defaultMessage: 'this app',
    description: 'Fallback app name in the empty app-chat heading.',
  },
  'chat.build.building': {
    defaultMessage: 'Building…',
    description: 'App chat build banner when no more specific build phase is available.',
  },
  'chat.build.connectors': {
    defaultMessage: 'Building connectors…',
    description: 'App chat build banner during connector compilation.',
  },
  'chat.build.deploying': {
    defaultMessage: 'Deploying…',
    description: 'App chat build banner during deployment.',
  },
  'chat.build.image': {
    defaultMessage: 'Building image…',
    description: 'App chat build banner during container image creation.',
  },
  'chat.build.migrations': {
    defaultMessage: 'Running migrations…',
    description: 'App chat build banner during migration validation.',
  },
  'chat.build.tasks': {
    defaultMessage: 'Building {done}/{total} task | Building {done}/{total} tasks',
    description: 'App chat build progress. done is the completed task count and total is the total task count.',
  },
  'chat.checkpoint.compacted': {
    defaultMessage: 'compacted',
    description: 'Label on a chat divider where context was compacted.',
  },
  'chat.checkpoint.contextCleared': {
    defaultMessage: 'context cleared',
    description: 'Label on a chat divider where conversation context was cleared.',
  },
  'chat.checkpoint.tokensFreed': {
    defaultMessage: '{formattedCount} token freed | {formattedCount} tokens freed',
    description: 'Token count shown on a context checkpoint divider. formattedCount is locale-formatted and count selects the plural form.',
  },
  'chat.confirmation.allowAction': {
    defaultMessage: 'Allow this action?',
    description: 'Question shown next to a tool call that requires user approval.',
  },
  'chat.confirmation.required': {
    defaultMessage: 'Confirmation required',
    description: 'Heading for a pending chat action that requires confirmation.',
  },
  'chat.confirmation.requiredPrefix': {
    defaultMessage: 'Confirmation required:',
    description: 'Prefix before a raw tool name when a system-assistant action requires confirmation.',
  },
  'chat.error.approvalFailed': {
    defaultMessage: 'Approval failed',
    description: 'Toast summary when approving an app-chat action fails.',
  },
  'chat.error.approveFailed': {
    defaultMessage: 'Approve failed',
    description: 'Toast summary when approving a system-assistant action fails.',
  },
  'chat.error.cannotResumeWithoutConversation': {
    defaultMessage: 'Cannot resume without an active conversation',
    description: 'Local error when a system-assistant confirmation is resumed without a conversation.',
  },
  'chat.error.loadChatFailed': {
    defaultMessage: 'Failed to load chat',
    description: 'Toast summary when a system-assistant conversation cannot be loaded.',
  },
  'chat.error.loadMoreFailed': {
    defaultMessage: 'Failed to load more',
    description: 'Toast summary when more system-assistant runs cannot be loaded.',
  },
  'chat.error.loadRunsFailed': {
    defaultMessage: 'Failed to load runs',
    description: 'Toast summary when system-assistant runs cannot be loaded.',
  },
  'chat.error.noActiveConversation': {
    defaultMessage: 'No active conversation',
    description: 'Local error when a system-assistant prompt has no conversation target.',
  },
  'chat.error.rejectFailed': {
    defaultMessage: 'Reject failed',
    description: 'Toast summary when rejecting a system-assistant action fails.',
  },
  'chat.error.rejectionFailed': {
    defaultMessage: 'Rejection failed',
    description: 'Toast summary when rejecting an app-chat action fails.',
  },
  'chat.error.runFailed': {
    defaultMessage: 'Run failed.',
    description: 'Local fallback in a chat error message when a run supplies no error text.',
  },
  'chat.error.sendFailed': {
    defaultMessage: 'Send failed',
    description: 'Toast summary when a chat message cannot be sent.',
  },
  'chat.error.startFailed': {
    defaultMessage: 'Start failed',
    description: 'Toast summary when a stopped app cannot be started from chat.',
  },
  'chat.error.uploadFailed': {
    defaultMessage: 'Upload failed',
    description: 'Toast summary when a chat attachment cannot be uploaded.',
  },
  'chat.feed.newChat': {
    defaultMessage: 'New chat',
    description: 'Fallback title for an untitled system-assistant conversation in the conversation feed.',
  },
  'chat.feed.untitledConversation': {
    defaultMessage: 'Untitled conversation',
    description: 'Fallback title for an untitled app conversation in the conversation feed.',
  },
  'chat.file.fallbackName': {
    defaultMessage: 'file',
    description: 'Fallback label for a chat file attachment that has no filename.',
  },
  'chat.message.cancelled': {
    defaultMessage: '(cancelled)',
    description: 'Marker on a chat response that the user cancelled.',
  },
  'chat.message.errorLabel': {
    defaultMessage: 'Error',
    description: 'Uppercase-style label above a persisted run error message.',
  },
  'chat.message.systemLabel': {
    defaultMessage: 'System',
    description: 'Uppercase-style label above a system message in app chat.',
  },
  'chat.message.upgradeLabel': {
    defaultMessage: 'Upgrade',
    description: 'Uppercase-style label above an app-upgrade message in chat.',
  },
  'chat.slash.clearDescription': {
    defaultMessage: 'Clear conversation context',
    description: 'Description of the /clear command in the app-chat command menu.',
  },
  'chat.slash.compactDescription': {
    defaultMessage: 'Summarize and compact context',
    description: 'Description of the /compact command in the app-chat command menu.',
  },
  'chat.systemAgent.assistantDescription': {
    defaultMessage: 'In-Airlock chat for managing apps, bridges, connections, members, and runs through your own permissions.',
    description: 'Description of the Airlock Assistant on its overview page.',
  },
  'chat.systemAgent.assistantName': {
    defaultMessage: 'Airlock Assistant',
    description: 'Product name of the built-in operator assistant.',
  },
  'chat.systemAgent.chat': {
    defaultMessage: 'Chat',
    description: 'Button that starts a conversation with the Airlock Assistant.',
  },
  'chat.systemAgent.column.cost': {
    defaultMessage: 'Cost',
    description: 'Cost column heading in the system-assistant run table.',
  },
  'chat.systemAgent.column.message': {
    defaultMessage: 'Message',
    description: 'Message-preview column heading in the system-assistant run table.',
  },
  'chat.systemAgent.column.started': {
    defaultMessage: 'Started',
    description: 'Start-time column heading in the system-assistant run table.',
  },
  'chat.systemAgent.column.status': {
    defaultMessage: 'Status',
    description: 'Status column heading in the system-assistant run table.',
  },
  'chat.systemAgent.column.trigger': {
    defaultMessage: 'Trigger',
    description: 'Trigger-type column heading in the system-assistant run table.',
  },
  'chat.systemAgent.loadMore': {
    defaultMessage: 'Load more',
    description: 'Button that loads more system-assistant runs.',
  },
  'chat.systemAgent.noRuns': {
    defaultMessage: 'No runs yet. Start a chat to do something.',
    description: 'Empty state in the system-assistant run list.',
  },
  'chat.systemAgent.operator': {
    defaultMessage: 'Operator',
    description: 'Badge identifying the Airlock Assistant as an operator assistant.',
  },
  'chat.systemAgent.runs': {
    defaultMessage: 'Runs',
    description: 'Heading for the system-assistant run list.',
  },
  'chat.systemChat.emptyExistingPrefix': {
    defaultMessage: 'Conversation with',
    description: 'Prefix before the assistant name in an empty existing system conversation.',
  },
  'chat.systemChat.assistantName': {
    defaultMessage: 'the Airlock Assistant',
    description: 'Assistant name following "Conversation with" in the system-chat empty state.',
  },
  'chat.systemChat.emptyHint': {
    defaultMessage: "Ask me anything - list your apps, trigger an upgrade, manage bridges, inspect runs. It's saved as a new conversation once you send.",
    description: 'Instruction shown in an empty system-assistant conversation.',
  },
  'chat.systemChat.emptyNewPrefix': {
    defaultMessage: 'New conversation with',
    description: 'Prefix before the assistant name in an empty new system conversation.',
  },
  'chat.systemChat.placeholder': {
    defaultMessage: 'Ask me anything…',
    description: 'Placeholder in the system-assistant chat composer.',
  },
  'chat.systemChat.pendingPlaceholder': {
    defaultMessage: 'Approve or reject the pending tool call above first.',
    description: 'Disabled composer placeholder while a system-assistant tool call awaits confirmation.',
  },
  'chat.tool.a2aCall': {
    defaultMessage: 'A2A Call',
    description: 'Human-facing label for the framework promptAgent tool.',
  },
  'chat.tool.a2aCallWithAgent': {
    defaultMessage: 'A2A Call ({agent})',
    description: 'Human-facing label for the framework promptAgent tool. agent is the unchanged target agent slug.',
  },
  'chat.tool.code': {
    defaultMessage: 'Code',
    description: 'Human-facing label for the framework run_js tool.',
  },
  'chat.tool.executionDenied': {
    defaultMessage: 'Tool call execution denied.',
    description: 'Local fallback shown when a denied tool result provides no reason.',
  },
  'chat.tool.moreLines': {
    defaultMessage: '… {formattedCount} more line - click to expand | … {formattedCount} more lines - click to expand',
    description: 'Collapsed tool-output hint. formattedCount is locale-formatted and count selects the plural form.',
  },
  'chat.tool.status.confirmation': {
    defaultMessage: 'confirmation',
    description: 'Live tool-call status while the call awaits confirmation.',
  },
  'chat.tool.status.denied': {
    defaultMessage: 'denied',
    description: 'Live tool-call status after the user or policy denies it.',
  },
  'chat.tool.status.error': {
    defaultMessage: 'error',
    description: 'Live tool-call status after it fails.',
  },
  'chat.tool.status.running': {
    defaultMessage: 'running',
    description: 'Live tool-call status while it is running.',
  },
})
