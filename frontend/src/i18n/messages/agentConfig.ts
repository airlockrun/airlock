import { defineMessages } from './define'

export const agentConfigMessages = defineMessages({
  'agentConfig.common.save': {
    defaultMessage: 'Save',
    description: 'Label for a button that saves app configuration changes.',
  },
  'agentConfig.common.saveFailed': {
    defaultMessage: 'Save failed',
    description: 'Fallback error shown when app configuration could not be saved and the server supplied no error.',
  },
  'agentConfig.common.cancel': {
    defaultMessage: 'Cancel',
    description: 'Label for a button that closes an app configuration dialog without applying changes.',
  },
  'agentConfig.common.add': {
    defaultMessage: 'Add',
    description: 'Label for a button that adds the item selected in an app configuration dialog.',
  },
  'agentConfig.common.edit': {
    defaultMessage: 'Edit',
    description: 'Label for a button that edits a configured app item.',
  },
  'agentConfig.common.remove': {
    defaultMessage: 'Remove',
    description: 'Label for an app configuration action or column that removes an item.',
  },
  'agentConfig.common.name': {
    defaultMessage: 'Name',
    description: 'Table column heading for the name of a tool or app.',
  },
  'agentConfig.common.description': {
    defaultMessage: 'Description',
    description: 'Table column heading for an externally supplied item description.',
  },
  'agentConfig.common.access': {
    defaultMessage: 'Access',
    description: 'Table column heading for the access level assigned to an item.',
  },
  'agentConfig.common.actions': {
    defaultMessage: 'Actions',
    description: 'Table column heading for controls that act on an app configuration item.',
  },

  'agentConfig.accessLevel.public': {
    defaultMessage: 'Public',
    description: 'Display label for the public access level on app tools, routes, and sibling connections.',
  },
  'agentConfig.accessLevel.user': {
    defaultMessage: 'User',
    description: 'Display label for the signed-in user access level on app tools, routes, and sibling connections.',
  },
  'agentConfig.accessLevel.admin': {
    defaultMessage: 'Admin',
    description: 'Display label for the administrator access level on app tools, routes, and sibling connections.',
  },

  'agentConfig.access.title': {
    defaultMessage: 'Access',
    description: 'Heading for the app configuration tab that controls external access.',
  },
  'agentConfig.access.description': {
    defaultMessage: 'How this app can be reached from outside. Who can use it is set under Members.',
    description: 'Introduction to app external access settings; Members is the name of another configuration tab.',
  },
  'agentConfig.access.mcpEnabled': {
    defaultMessage: 'Let other apps connect to this app (MCP)',
    description: 'Label for the switch that enables authenticated MCP connections to the app.',
  },
  'agentConfig.access.mcpEnabledHint': {
    defaultMessage: 'For tools like Claude Desktop and other apps.',
    description: 'Help text explaining what can use the app MCP connection.',
  },
  'agentConfig.access.connectionUrl': {
    defaultMessage: 'Connection URL',
    description: 'Label above the authenticated MCP endpoint URL.',
  },
  'agentConfig.access.clickToCopy': {
    defaultMessage: 'Click to copy',
    description: 'Tooltip on a connection URL that can be copied.',
  },
  'agentConfig.access.allowPublicMcp': {
    defaultMessage: 'Allow connecting without signing in',
    description: 'Label for the switch that permits anonymous MCP connections.',
  },
  'agentConfig.access.allowPublicMcpHint': {
    defaultMessage: 'Anyone can connect; only public tools are exposed.',
    description: 'Help text describing the scope of anonymous MCP access.',
  },
  'agentConfig.access.publicUrl': {
    defaultMessage: 'Public URL (no sign-in)',
    description: 'Label above the anonymous MCP endpoint URL.',
  },
  'agentConfig.access.allowPublicRoutes': {
    defaultMessage: 'Allow public web pages without signing in',
    description: 'Label for the switch that permits anonymous access to app routes marked public.',
  },
  'agentConfig.access.allowPublicRoutesHint': {
    defaultMessage: "Lets anyone open this app's pages marked public.",
    description: 'Help text describing anonymous access to public app pages.',
  },
  'agentConfig.access.saved': {
    defaultMessage: 'Saved',
    description: 'Success toast shown after external access settings are saved.',
  },
  'agentConfig.access.urlCopied': {
    defaultMessage: 'URL copied',
    description: 'Success toast shown after an app connection URL is copied.',
  },
  'agentConfig.access.copyFailed': {
    defaultMessage: 'Copy failed - select the URL and copy manually',
    description: 'Warning shown when the browser cannot copy an app connection URL automatically.',
  },

  'agentConfig.envVars.patternError': {
    defaultMessage: 'Value must match pattern: {pattern}',
    description: 'Validation error for an environment variable value. Pattern is a raw regular expression and must not be translated.',
  },
  'agentConfig.envVars.updated': {
    defaultMessage: '{slug} updated',
    description: 'Success toast after an environment variable is updated. Slug is the raw environment variable name.',
  },
  'agentConfig.envVars.clearSecretConfirmation': {
    defaultMessage: 'Clear the configured value for {slug}? The app will fail to read this until you set a new value.',
    description: 'Confirmation before clearing a secret environment variable. Slug is the raw environment variable name.',
  },
  'agentConfig.envVars.clearValueConfirmation': {
    defaultMessage: 'Clear the configured value for {slug}? The app will fall back to the default ("{defaultValue}").',
    description: 'Confirmation before clearing a non-secret environment variable. Slug and defaultValue are raw app data.',
  },
  'agentConfig.envVars.clearValue': {
    defaultMessage: 'Clear value',
    description: 'Title and accessible label for clearing an environment variable value.',
  },
  'agentConfig.envVars.clear': {
    defaultMessage: 'Clear',
    description: 'Destructive confirmation button for clearing an environment variable value.',
  },
  'agentConfig.envVars.cleared': {
    defaultMessage: '{slug} cleared',
    description: 'Success toast after an environment variable is cleared. Slug is the raw environment variable name.',
  },
  'agentConfig.envVars.clearFailed': {
    defaultMessage: 'Clear failed',
    description: 'Fallback error when an environment variable could not be cleared and the server supplied no error.',
  },
  'agentConfig.envVars.emptyBeforeIdentifier': {
    defaultMessage: 'No environment variables registered. Builders declare them via',
    description: 'Empty-state text immediately before the agent.RegisterEnvVar code identifier.',
  },
  'agentConfig.envVars.emptyAfterIdentifier': {
    defaultMessage: '.',
    description: 'Punctuation immediately after the agent.RegisterEnvVar code identifier in the environment-variable empty state.',
  },
  'agentConfig.envVars.slug': {
    defaultMessage: 'Slug',
    description: 'Table column heading for a raw environment-variable or app slug.',
  },
  'agentConfig.envVars.secret': {
    defaultMessage: 'secret',
    description: 'Badge marking an environment variable as secret.',
  },
  'agentConfig.envVars.value': {
    defaultMessage: 'Value',
    description: 'Environment-variable table heading and input label.',
  },
  'agentConfig.envVars.notSet': {
    defaultMessage: 'not set',
    description: 'Status shown when an environment variable has no configured or default value.',
  },
  'agentConfig.envVars.defaultValue': {
    defaultMessage: '{value} (default)',
    description: 'Display of a raw environment variable default value when no configured value exists.',
  },
  'agentConfig.envVars.rotate': {
    defaultMessage: 'Rotate',
    description: 'Button label for replacing a configured secret environment variable.',
  },
  'agentConfig.envVars.set': {
    defaultMessage: 'Set',
    description: 'Button label for setting an environment variable that is not configured.',
  },
  'agentConfig.envVars.updateDialogTitle': {
    defaultMessage: 'Update {slug}',
    description: 'Dialog title for updating an environment variable. Slug is the raw environment variable name.',
  },
  'agentConfig.envVars.setDialogTitle': {
    defaultMessage: 'Set {slug}',
    description: 'Dialog title for setting an environment variable. Slug is the raw environment variable name.',
  },
  'agentConfig.envVars.secretExplanation': {
    defaultMessage: "This value is treated as a secret. It will be redacted from LLM input, and you won't be able to read it back from this UI - only rotate.",
    description: 'Explanation in the editor for a secret environment variable.',
  },
  'agentConfig.envVars.patternLabel': {
    defaultMessage: 'Pattern:',
    description: 'Label before the raw validation pattern for an environment variable.',
  },
  'agentConfig.envVars.defaultLabel': {
    defaultMessage: 'Default:',
    description: 'Label before the raw default value for an environment variable.',
  },

  'agentConfig.members.allUsers': {
    defaultMessage: 'All users',
    description: 'Display name of the built-in group containing every registered user.',
  },
  'agentConfig.members.roleAdmin': {
    defaultMessage: 'Admin',
    description: 'Human-readable option label for the admin app-member role.',
  },
  'agentConfig.members.roleUser': {
    defaultMessage: 'User',
    description: 'Human-readable option label for the user app-member role.',
  },
  'agentConfig.members.rolePublic': {
    defaultMessage: 'Public',
    description: 'Human-readable option label for the public app-member role.',
  },
  'agentConfig.members.addFailed': {
    defaultMessage: 'Failed to add member',
    description: 'Fallback error when an app member could not be added and the server supplied no error.',
  },
  'agentConfig.members.removeConfirmation': {
    defaultMessage: 'Remove {member} from this app?',
    description: 'Confirmation before removing an app member. Member is user or group data and must not be translated.',
  },
  'agentConfig.members.confirmRemoval': {
    defaultMessage: 'Confirm Removal',
    description: 'Title of the dialog confirming removal of an app member.',
  },
  'agentConfig.members.removeFailed': {
    defaultMessage: 'Failed to remove member',
    description: 'Fallback error when an app member could not be removed and the server supplied no error.',
  },
  'agentConfig.members.empty': {
    defaultMessage: 'No members.',
    description: 'Empty state for the app members table.',
  },
  'agentConfig.members.member': {
    defaultMessage: 'Member',
    description: 'Table column heading for an app member.',
  },
  'agentConfig.members.displayName': {
    defaultMessage: 'Display Name',
    description: 'Table column heading for an app member display name.',
  },
  'agentConfig.members.role': {
    defaultMessage: 'Role',
    description: 'App-member table heading and role field label.',
  },
  'agentConfig.members.addMember': {
    defaultMessage: 'Add Member',
    description: 'Button label and dialog title for adding an app member.',
  },
  'agentConfig.members.user': {
    defaultMessage: 'User',
    description: 'Label for the user selector in the add-member dialog.',
  },
  'agentConfig.members.selectUser': {
    defaultMessage: 'Select a user',
    description: 'Placeholder in the user selector in the add-member dialog.',
  },

  'agentConfig.models.loadFailed': {
    defaultMessage: 'Failed to load model config',
    description: 'Fallback error when app model configuration could not be loaded and the server supplied no error.',
  },
  'agentConfig.models.capabilityText': {
    defaultMessage: 'Text',
    description: 'Display label for the text-generation capability of an app model slot.',
  },
  'agentConfig.models.buildModel': {
    defaultMessage: 'Build Model',
    description: 'Label for the model used to build the app.',
  },
  'agentConfig.models.executionModel': {
    defaultMessage: 'Execution Model (Text)',
    description: 'Label for the default text model used while the app runs.',
  },
  'agentConfig.models.vision': {
    defaultMessage: 'Vision',
    description: 'Label for the app vision model capability.',
  },
  'agentConfig.models.stt': {
    defaultMessage: 'STT',
    description: 'Label for the app speech-to-text model capability.',
  },
  'agentConfig.models.tts': {
    defaultMessage: 'TTS',
    description: 'Label for the app text-to-speech model capability.',
  },
  'agentConfig.models.imageGen': {
    defaultMessage: 'Image Gen',
    description: 'Label for the app image-generation model capability.',
  },
  'agentConfig.models.embedding': {
    defaultMessage: 'Embedding',
    description: 'Label for the app text-embedding model capability.',
  },
  'agentConfig.models.webSearch': {
    defaultMessage: 'Web Search',
    description: 'Label for the app web-search provider and model capability.',
  },
  'agentConfig.models.default': {
    defaultMessage: 'Default',
    description: 'Placeholder or value shown when an app uses the system default model.',
  },
  'agentConfig.models.defaultWithModel': {
    defaultMessage: 'Default ({model})',
    description: 'Model picker placeholder showing the raw model name that the default resolves to.',
  },
  'agentConfig.models.defaultResolvedModel': {
    defaultMessage: 'Default · {model}',
    description: 'Read-only model value showing the raw model name that the default resolves to.',
  },
  'agentConfig.models.buildModelHelp': {
    defaultMessage: 'Override the system default build model for this app.',
    description: 'Help text for the app build model override.',
  },
  'agentConfig.models.executionModelHelp': {
    defaultMessage: 'Runtime default when the app makes text LLM calls without a specific slug.',
    description: 'Help text for the app execution text model override.',
  },
  'agentConfig.models.visionHelp': {
    defaultMessage: 'Image → text tasks (VM attachToContext on images, explicit vision capability LLM calls).',
    description: 'Help text for the app vision model override. VM and attachToContext are technical identifiers.',
  },
  'agentConfig.models.sttHelp': {
    defaultMessage: 'Speech-to-text - used by agent.TranscriptionModel and the VM transcribeAudio built-in.',
    description: 'Help text for the app speech-to-text model override. Code identifiers must remain unchanged.',
  },
  'agentConfig.models.ttsHelp': {
    defaultMessage: 'Text-to-speech - used by agent.SpeechModel and the VM generateSpeech built-in.',
    description: 'Help text for the app text-to-speech model override. Code identifiers must remain unchanged.',
  },
  'agentConfig.models.imageGenHelp': {
    defaultMessage: 'Text-to-image - used by agent.ImageModel and the VM generateImage built-in.',
    description: 'Help text for the app image-generation model override. Code identifiers must remain unchanged.',
  },
  'agentConfig.models.embeddingHelp': {
    defaultMessage: 'Text embeddings - used by agent.EmbeddingModel and the VM embed built-in.',
    description: 'Help text for the app embedding model override. Code identifiers must remain unchanged.',
  },
  'agentConfig.models.webSearchHelp': {
    defaultMessage: 'Web search backend + model. Pick "Provider default" to let the backend choose its model.',
    description: 'Help text for the app web-search configuration. Provider default names the provider-only picker option.',
  },
  'agentConfig.models.saved': {
    defaultMessage: 'Models saved',
    description: 'Success toast after app model configuration is saved.',
  },
  'agentConfig.models.capabilityOverrides': {
    defaultMessage: 'Capability overrides',
    description: 'Heading above per-app model capability overrides.',
  },
  'agentConfig.models.capabilityOverridesDescription': {
    defaultMessage: 'Override system defaults for this app. Leave empty for Default.',
    description: 'Instructions above the app model capability override fields.',
  },
  'agentConfig.models.modelSlots': {
    defaultMessage: 'Model slots',
    description: 'Heading above the named model slots declared by an app.',
  },
  'agentConfig.models.modelSlotsBeforeIdentifier': {
    defaultMessage: 'Named slots the app declared via',
    description: 'Model-slot guidance immediately before the RegisterModel code identifier.',
  },
  'agentConfig.models.modelSlotsAfterIdentifier': {
    defaultMessage: '. Assigning a model binds the slot directly; empty falls through to the capability override above, then the system default.',
    description: 'Model-slot guidance immediately after the RegisterModel code identifier.',
  },
  'agentConfig.models.title': {
    defaultMessage: 'Models',
    description: 'Heading for the read-only app model configuration.',
  },
  'agentConfig.models.readonlyDescription': {
    defaultMessage: 'Models configured for this app. Editing requires manager access and app admin.',
    description: 'Explanation shown to a user who can view but cannot edit app model configuration.',
  },

  'agentConfig.routes.empty': {
    defaultMessage: 'No routes registered.',
    description: 'Empty state for the app routes table.',
  },
  'agentConfig.routes.method': {
    defaultMessage: 'Method',
    description: 'Table column heading for a raw HTTP route method.',
  },
  'agentConfig.routes.path': {
    defaultMessage: 'Path',
    description: 'Table column heading for a raw route or webhook path.',
  },

  'agentConfig.siblings.addFailed': {
    defaultMessage: 'add failed',
    description: 'Fallback error when a sibling app could not be added and the server supplied no error.',
  },
  'agentConfig.siblings.updateFailed': {
    defaultMessage: 'update failed',
    description: 'Fallback error when sibling app access could not be updated and the server supplied no error.',
  },
  'agentConfig.siblings.removeFailed': {
    defaultMessage: 'remove failed',
    description: 'Fallback error when a sibling app could not be removed and the server supplied no error.',
  },
  'agentConfig.siblings.removeConfirmation': {
    defaultMessage: "Remove {name} from this app's address book? This app's LLM will lose its {binding} binding on the next build.",
    description: 'Confirmation before removing a sibling app. Name is app data and binding is a generated raw agent_slug identifier.',
  },
  'agentConfig.siblings.removeSibling': {
    defaultMessage: 'Remove sibling',
    description: 'Title of the confirmation dialog for removing a sibling app.',
  },
  'agentConfig.siblings.title': {
    defaultMessage: 'Sibling apps',
    description: 'Heading above the apps in this app address book.',
  },
  'agentConfig.siblings.description': {
    defaultMessage: "This app will be able to call the other apps listed here. Max access caps what this app can do on each; it auto-downgrades (and the row drops) if the target's owner lowers or revokes access.",
    description: 'Explanation of outbound sibling apps and their effective maximum access.',
  },
  'agentConfig.siblings.maxAccess': {
    defaultMessage: 'Max access',
    description: 'Table heading and field label for the maximum access a sibling app call can receive.',
  },
  'agentConfig.siblings.cappedTitle': {
    defaultMessage: "Set to {access}, capped by the target's current grant",
    description: 'Tooltip explaining a reduced sibling access value. Access is the localized label for the configured access level.',
  },
  'agentConfig.siblings.cappedFrom': {
    defaultMessage: 'capped from {access}',
    description: 'Short note beside reduced sibling access. Access is the localized label for the configured access level.',
  },
  'agentConfig.siblings.empty': {
    defaultMessage: 'No sibling apps yet.',
    description: 'Empty state for this app sibling address book.',
  },
  'agentConfig.siblings.addSibling': {
    defaultMessage: 'Add sibling',
    description: 'Button label and dialog title for adding an app to the sibling address book.',
  },
  'agentConfig.siblings.connectedTitle': {
    defaultMessage: 'Connected to this app',
    description: 'Heading above apps that have this app in their address book.',
  },
  'agentConfig.siblings.connectedDescription': {
    defaultMessage: 'Apps that have added this one to their address book - who can call this app via A2A, and the live max access each has.',
    description: 'Explanation of inbound sibling app connections and their effective maximum access.',
  },
  'agentConfig.siblings.owner': {
    defaultMessage: 'Owner',
    description: 'Table column heading for the externally supplied owner name of a sibling app.',
  },
  'agentConfig.siblings.noInbound': {
    defaultMessage: 'No apps call this one.',
    description: 'Empty state for apps that call this app through A2A.',
  },
  'agentConfig.siblings.addDialogDescription': {
    defaultMessage: "Apps this app's owner has access to.",
    description: 'Explanation of which apps are available in the add-sibling picker.',
  },
  'agentConfig.siblings.app': {
    defaultMessage: 'App',
    description: 'Label for the app picker in the add-sibling dialog.',
  },
  'agentConfig.siblings.pickApp': {
    defaultMessage: 'Pick an app',
    description: 'Placeholder in the app picker in the add-sibling dialog.',
  },
  'agentConfig.siblings.maxAccessHelp': {
    defaultMessage: "The ceiling for what this app can do when it calls the sibling. The real access is still floored by the driving user's and this app's owner's access on the target.",
    description: 'Help text for maximum access when adding a sibling app.',
  },
  'agentConfig.siblings.editMaxAccess': {
    defaultMessage: 'Edit max access',
    description: 'Title of the dialog for editing sibling maximum access.',
  },
  'agentConfig.siblings.editMaxAccessHelp': {
    defaultMessage: "Operator intent. The effective ceiling is still floored by the target's current grant.",
    description: 'Help text for editing the intended maximum access of a sibling app.',
  },

  'agentConfig.tools.empty': {
    defaultMessage: 'No tools registered.',
    description: 'Empty state for the app tools table.',
  },

  'agentConfig.webhooks.never': {
    defaultMessage: 'Never',
    description: 'Value shown when an app webhook has never received a request.',
  },
  'agentConfig.webhooks.empty': {
    defaultMessage: 'No webhooks registered.',
    description: 'Empty state for the app webhooks table.',
  },
  'agentConfig.webhooks.verifyMode': {
    defaultMessage: 'Verify Mode',
    description: 'Table column heading for a raw webhook verification mode.',
  },
  'agentConfig.webhooks.secret': {
    defaultMessage: 'Secret',
    description: 'Table column heading indicating whether a webhook secret exists.',
  },
  'agentConfig.webhooks.lastReceived': {
    defaultMessage: 'Last Received',
    description: 'Table column heading for the time an app webhook last received a request.',
  },
})
