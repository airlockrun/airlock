import { defineMessages } from './define'

export const agentMessages = defineMessages({
  'agents.action.cancel': {
    defaultMessage: 'Cancel',
    description: 'Label for buttons that close an app dialog without applying changes.',
  },
  'agents.action.claim': {
    defaultMessage: 'Claim',
    description: 'Action that adds the current workspace administrator to an app as an administrator.',
  },
  'agents.action.clone': {
    defaultMessage: 'Clone',
    description: 'Action that creates a copy of an app.',
  },
  'agents.action.delete': {
    defaultMessage: 'Delete',
    description: 'Destructive action that permanently deletes an app.',
  },
  'agents.action.open': {
    defaultMessage: 'Open',
    description: 'Action that opens an app the current user can access.',
  },
  'agents.action.rebuild': {
    defaultMessage: 'Rebuild',
    description: 'Action that rebuilds an app without requesting source changes.',
  },
  'agents.action.rebuildLowercase': {
    defaultMessage: 'rebuild',
    description: 'Emphasized lowercase term in help text about rebuilding an app.',
  },
  'agents.action.rename': {
    defaultMessage: 'Rename',
    description: 'Tooltip for the action that renames an app.',
  },
  'agents.action.retry': {
    defaultMessage: 'Retry',
    description: 'Label for retrying a failed app-related data request.',
  },
  'agents.action.save': {
    defaultMessage: 'Save',
    description: 'Label for saving app name and slug changes.',
  },
  'agents.action.start': {
    defaultMessage: 'Start',
    description: 'Lifecycle action that starts an app.',
  },
  'agents.action.stop': {
    defaultMessage: 'Stop',
    description: 'Lifecycle action that stops an app.',
  },
  'agents.action.suspend': {
    defaultMessage: 'Suspend',
    description: 'Lifecycle action that suspends a running app until its next trigger.',
  },
  'agents.action.transfer': {
    defaultMessage: 'Transfer',
    description: 'Action that confirms transferring app ownership to another user.',
  },
  'agents.action.upgrade': {
    defaultMessage: 'Upgrade',
    description: 'Action that requests source changes and rebuilds an app.',
  },
  'agents.copy.copied': {
    defaultMessage: '{label} copied',
    description: 'Toast confirming that the named app setup value or command was copied. Preserve the interpolated label.',
  },
  'agents.copy.failed': {
    defaultMessage: 'Copy failed - select and copy {label} manually',
    description: 'Toast instructing the user to manually copy the named source value after clipboard access fails.',
  },
  'agents.copy.failedLowercase': {
    defaultMessage: 'Copy failed - select and copy {label} manually',
    description: 'Toast instructing the user to manually copy a lowercased setup label after clipboard access fails.',
  },
  'agents.status.building': {
    defaultMessage: 'Building',
    description: 'App lifecycle badge shown while the app is being built.',
  },
  'agents.status.draft': {
    defaultMessage: 'Draft',
    description: 'App lifecycle badge shown before an app build is started.',
  },
  'agents.status.error': {
    defaultMessage: 'Error',
    description: 'App lifecycle badge shown when an app build or startup failed.',
  },
  'agents.status.inactive': {
    defaultMessage: 'Inactive',
    description: 'App lifecycle badge shown when an app is inactive.',
  },
  'agents.status.running': {
    defaultMessage: 'Running',
    description: 'App lifecycle badge shown when its container is running.',
  },
  'agents.status.stopped': {
    defaultMessage: 'Stopped',
    description: 'App lifecycle badge shown when the app was manually stopped.',
  },
  'agents.status.suspended': {
    defaultMessage: 'Suspended',
    description: 'App lifecycle badge shown when no container is running but the app can resume automatically.',
  },
  'agents.list.title': {
    defaultMessage: 'Apps',
    description: 'Heading for the current user’s app list.',
  },
  'agents.list.assistantName': {
    defaultMessage: 'Airlock Assistant',
    description: 'Product name of the built-in operator app. Keep the product name unchanged.',
  },
  'agents.list.operatorSlug': {
    defaultMessage: 'operator',
    description: 'Subtitle identifying the built-in Airlock Assistant as the operator.',
  },
  'agents.list.operatorBadge': {
    defaultMessage: 'Operator',
    description: 'Badge identifying the built-in Airlock Assistant as the workspace operator.',
  },
  'agents.list.assistantDescription': {
    defaultMessage: 'Manage apps, bridges, connections, members and runs through chat - with your own permissions.',
    description: 'Description of what the built-in Airlock Assistant can manage for the current user.',
  },
  'agents.list.empty': {
    defaultMessage: 'No apps yet. Create your first app to get started.',
    description: 'Empty state shown when the current user has no apps.',
  },
  'agents.list.manageAll': {
    defaultMessage: 'Manage all apps in this workspace',
    description: 'Link from the app list to the administrator governance view.',
  },
  'agents.governance.title': {
    defaultMessage: 'Manage apps',
    description: 'Heading for the administrator app governance view.',
  },
  'agents.governance.total': {
    defaultMessage: '{formattedCount} total',
    description: 'Badge showing the locale-formatted total number of apps in the workspace. {count} is the numeric count.',
  },
  'agents.governance.descriptionBeforeClaim': {
    defaultMessage: "Every app in this workspace, including ones you're not a member of. As an admin you can stop, start, or delete any app here for governance. Reading an app's conversations or configuration still requires access - use",
    description: 'Governance introduction before the emphasized Claim action name.',
  },
  'agents.governance.descriptionAfterClaim': {
    defaultMessage: 'to add yourself as an admin first.',
    description: 'Governance introduction after the emphasized Claim action name.',
  },
  'agents.governance.filterPlaceholder': {
    defaultMessage: 'Filter by name, slug, or owner',
    description: 'Placeholder for filtering the workspace app governance table.',
  },
  'agents.governance.empty': {
    defaultMessage: 'No apps in this workspace yet.',
    description: 'Empty state for the workspace app governance table.',
  },
  'agents.governance.column.app': {
    defaultMessage: 'App',
    description: 'Governance table column containing app names and slugs.',
  },
  'agents.governance.column.owner': {
    defaultMessage: 'Owner',
    description: 'Governance table column containing each app owner.',
  },
  'agents.governance.column.status': {
    defaultMessage: 'Status',
    description: 'Governance table column containing app lifecycle status.',
  },
  'agents.governance.column.yourAccess': {
    defaultMessage: 'Your access',
    description: 'Governance table column describing the current user’s access to each app.',
  },
  'agents.governance.you': {
    defaultMessage: 'You',
    description: 'Owner value shown when the current user owns the app.',
  },
  'agents.governance.access.owner': {
    defaultMessage: 'owner',
    description: 'Access badge shown when the current user owns the app.',
  },
  'agents.governance.access.admin': {
    defaultMessage: 'admin',
    description: 'Access badge shown when the current user administers the app.',
  },
  'agents.governance.access.member': {
    defaultMessage: 'member',
    description: 'Access badge shown when the current user is an app member.',
  },
  'agents.governance.access.notMember': {
    defaultMessage: 'not a member',
    description: 'Access value shown when the current user has no membership in the app.',
  },
  'agents.governance.claimed': {
    defaultMessage: "Claimed {name} - you're now an admin",
    description: 'Toast confirming the current user claimed the named app. Preserve the app name.',
  },
  'agents.governance.claimFailed': {
    defaultMessage: 'Claim failed',
    description: 'Fallback error shown when claiming an app fails.',
  },
  'agents.governance.deleteTitle': {
    defaultMessage: 'Delete app',
    description: 'Heading for the governance dialog that permanently deletes an app.',
  },
  'agents.governance.deleteConfirm': {
    defaultMessage: 'Permanently delete "{name}" (owned by {owner})? This removes its container, image, data, and history. This cannot be undone.',
    description: 'Governance confirmation before permanently deleting an app. Preserve the app and owner names.',
  },
  'agents.governance.unknownOwner': {
    defaultMessage: 'unknown',
    description: 'Fallback owner label when an app owner name is unavailable.',
  },
  'agents.governance.deleteAria': {
    defaultMessage: 'Delete app',
    description: 'Accessible label for the governance table button that deletes an app.',
  },
  'agents.source.mode.readWriteDescription': {
    defaultMessage: 'Read/write - Airlock may push code changes',
    description: 'Source mode option allowing Airlock to push source changes to the Git remote.',
  },
  'agents.source.mode.readOnlyDescription': {
    defaultMessage: 'Read-only - Git is authoritative',
    description: 'Source mode option making the configured Git repository authoritative.',
  },
  'agents.source.mode.label': {
    defaultMessage: 'Mode',
    description: 'Label for the connected Git source mode.',
  },
  'agents.source.mode.readOnly': {
    defaultMessage: 'Read-only',
    description: 'Value shown when a connected Git source is read-only.',
  },
  'agents.source.mode.readWrite': {
    defaultMessage: 'Read/write',
    description: 'Value shown when a connected Git source allows reads and writes.',
  },
  'agents.source.connected': {
    defaultMessage: 'Remote connected',
    description: 'Toast confirming a Git remote was connected to the app.',
  },
  'agents.source.connectFailed': {
    defaultMessage: 'Failed to connect remote',
    description: 'Fallback error shown when connecting an app Git remote fails.',
  },
  'agents.source.disconnectTitle': {
    defaultMessage: 'Disconnect remote?',
    description: 'Heading for the confirmation dialog that disconnects an app Git remote.',
  },
  'agents.source.disconnectConfirm': {
    defaultMessage: 'The app returns to internal-only mode. Future codegen commits stay local; webhook pushes from your remote are ignored. The local repo + image are untouched.',
    description: 'Explanation of the effects of disconnecting an app Git remote.',
  },
  'agents.source.disconnectAction': {
    defaultMessage: 'Disconnect',
    description: 'Action confirming that the app Git remote should be disconnected.',
  },
  'agents.source.disconnected': {
    defaultMessage: 'Remote disconnected',
    description: 'Toast confirming the app Git remote was disconnected.',
  },
  'agents.source.disconnectFailed': {
    defaultMessage: 'Failed to disconnect',
    description: 'Fallback error shown when disconnecting an app Git remote fails.',
  },
  'agents.source.internalDescription': {
    defaultMessage: "This app has no git remote. Connect one for a Git-based workflow, or use the Air CLI to work with Airlock's source directly.",
    description: 'Source tab explanation shown when the app has no Git remote.',
  },
  'agents.source.airCli': {
    defaultMessage: 'Air CLI',
    description: 'Name of the Air command-line interface. Keep the product name unchanged.',
  },
  'agents.source.airCliDescriptionBeforeCommand': {
    defaultMessage: "Install the launcher once, then clone the app. The launcher selects this Airlock's CLI version and opens login when needed. Inside the cloned repository, use",
    description: 'Air CLI setup explanation immediately before the immutable go tool air command.',
  },
  'agents.source.airCliDescriptionAfterCommand': {
    defaultMessage: 'to deploy changes.',
    description: 'Air CLI setup explanation immediately after the immutable go tool air command.',
  },
  'agents.source.installCommand': {
    defaultMessage: 'Install command',
    description: 'Human-readable label for the immutable Air CLI launcher installation command.',
  },
  'agents.source.cloneCommand': {
    defaultMessage: 'Clone command',
    description: 'Human-readable label for an immutable command that clones app source.',
  },
  'agents.source.deployCommand': {
    defaultMessage: 'Deploy command',
    description: 'Human-readable label for an immutable command that deploys app source.',
  },
  'agents.source.noCredentials': {
    defaultMessage: "You don't have any git credentials yet.",
    description: 'Source tab notice shown when the current user has no Git credentials.',
  },
  'agents.source.addPat': {
    defaultMessage: 'Add a PAT in Settings',
    description: 'Button leading to settings to add a Git personal access token.',
  },
  'agents.source.connectRepo': {
    defaultMessage: 'Connect a repo',
    description: 'Button opening the dialog to connect a Git repository to an app.',
  },
  'agents.source.remote': {
    defaultMessage: 'Remote',
    description: 'Label for the connected Git remote URL.',
  },
  'agents.source.url': {
    defaultMessage: 'URL',
    description: 'Human-readable label used when copying the immutable Git remote URL.',
  },
  'agents.source.branch': {
    defaultMessage: 'Branch',
    description: 'Label for the connected Git branch.',
  },
  'agents.source.credential': {
    defaultMessage: 'Credential',
    description: 'Label for the Git credential used by an app.',
  },
  'agents.source.lastSyncedRef': {
    defaultMessage: 'Last synced ref',
    description: 'Label for the immutable Git ref most recently synchronized by Airlock.',
  },
  'agents.source.command': {
    defaultMessage: 'Command',
    description: 'Generic human-readable label used when copying an immutable Git command.',
  },
  'agents.source.webhookSetup': {
    defaultMessage: "Webhook setup (paste these into your git provider's webhook settings)",
    description: 'Expandable heading for configuring the app webhook in a Git provider.',
  },
  'agents.source.payloadUrl': {
    defaultMessage: 'Payload URL',
    description: 'Label for the immutable webhook payload URL.',
  },
  'agents.source.webhookUrl': {
    defaultMessage: 'Webhook URL',
    description: 'Human-readable label used when copying the immutable webhook URL.',
  },
  'agents.source.secret': {
    defaultMessage: 'Secret',
    description: 'Label for the immutable webhook secret.',
  },
  'agents.source.webhookContentType': {
    defaultMessage: 'Content type:',
    description: 'Webhook setup prose immediately before the immutable application/json content type.',
  },
  'agents.source.webhookEventBeforePush': {
    defaultMessage: 'Event: just the',
    description: 'Webhook setup prose immediately before the immutable push event name.',
  },
  'agents.source.webhookEventAfterPush': {
    defaultMessage: 'event (GitHub/GitLab/etc).',
    description: 'Webhook setup prose after the immutable push event name. Keep provider names unchanged.',
  },
  'agents.source.webhookProviderFallback': {
    defaultMessage: "Other providers (Bitbucket, Gitea) aren't wired for signature verification yet - the polling fallback picks up pushes every 5 minutes.",
    description: 'Webhook setup note about signature verification and polling. Keep provider names unchanged.',
  },
  'agents.source.disconnectRemote': {
    defaultMessage: 'Disconnect remote',
    description: 'Button opening confirmation to disconnect the app Git remote.',
  },
  'agents.source.connectTitle': {
    defaultMessage: 'Connect a git remote',
    description: 'Heading for the dialog that connects a Git remote to an app.',
  },
  'agents.source.connectDescription': {
    defaultMessage: "Create an empty repo on your git provider, paste its HTTPS clone URL below, and pick a credential. Airlock will push the app's current state to it and use that repo as the source of truth.",
    description: 'Instructions for connecting an empty Git repository to the app.',
  },
  'agents.source.remoteUrlPlaceholder': {
    defaultMessage: 'https://github.com/your-org/your-app.git',
    description: 'Example immutable HTTPS Git clone URL. Do not translate or alter the URL.',
  },
  'agents.source.remoteUrl': {
    defaultMessage: 'Remote URL',
    description: 'Field label for the HTTPS Git remote URL.',
  },
  'agents.source.defaultBranch': {
    defaultMessage: 'Default branch',
    description: 'Field label for the app Git repository default branch.',
  },
  'agents.source.sourceMode': {
    defaultMessage: 'Source mode',
    description: 'Field label controlling how Airlock interacts with app Git source.',
  },
  'agents.source.readOnlyWarning': {
    defaultMessage: "Git is authoritative. Connecting replaces the app's source with this branch and disables Airlock codegen, local deploys, and source rollbacks.",
    description: 'Warning explaining the effects of connecting an app in read-only Git mode.',
  },
  'agents.source.connectAction': {
    defaultMessage: 'Connect',
    description: 'Action confirming connection of a Git remote to an app.',
  },
  'agents.create.action': {
    defaultMessage: 'Create App',
    description: 'Primary action that opens the app creation view.',
  },
  'agents.create.title': {
    defaultMessage: 'Create App',
    description: 'Heading for the app creation view.',
  },
  'agents.create.description': {
    defaultMessage: 'Generate from instructions, build from local source, or import an existing Git repository.',
    description: 'Introduction to the three available app creation modes.',
  },
  'agents.create.mode.generateTitle': {
    defaultMessage: 'Generate From Instructions',
    description: 'Title of the app creation mode that generates source from user instructions.',
  },
  'agents.create.mode.generateDescription': {
    defaultMessage: 'Describe what you need. Airlock generates the source and builds the first version.',
    description: 'Description of generating a new app from instructions.',
  },
  'agents.create.mode.localTitle': {
    defaultMessage: 'Deploy From Local Source',
    description: 'Title of the app creation mode that deploys locally authored source.',
  },
  'agents.create.mode.localDescription': {
    defaultMessage: 'Use OpenCode or another coding assistant to build locally and deploy with the Airlock CLI.',
    description: 'Description of deploying locally authored source. Keep product names unchanged.',
  },
  'agents.create.mode.gitTitle': {
    defaultMessage: 'Import From Git',
    description: 'Title of the app creation mode that imports an existing Git repository.',
  },
  'agents.create.mode.gitDescription': {
    defaultMessage: 'Clone an existing repo, build it as-is, and optionally keep it connected for future sync.',
    description: 'Description of importing an app from an existing Git repository.',
  },
  'agents.create.gitMode.importOnce': {
    defaultMessage: 'Import once - Airlock owns the copied source',
    description: 'Git import mode that copies source into Airlock and disconnects the remote.',
  },
  'agents.create.localSetupLoadFailed': {
    defaultMessage: 'Could not load the local setup commands. Refresh the page to try again.',
    description: 'Error shown when immutable local app setup commands cannot be loaded.',
  },
  'agents.create.localAssistantQuestion': {
    defaultMessage: 'Using a coding assistant?',
    description: 'Prompt introducing setup instructions intended for a coding assistant.',
  },
  'agents.create.localAssistantDescription': {
    defaultMessage: 'Copy the entire setup below into OpenCode, Claude Code, Codex, Cursor, or another coding assistant. It will ask what you want to build, help choose a name, and guide you through setup and deployment.',
    description: 'Instructions for giving the complete immutable setup block to a coding assistant. Keep product names unchanged.',
  },
  'agents.create.localTitle': {
    defaultMessage: 'Create with a coding assistant or terminal',
    description: 'Heading above the local app setup command block.',
  },
  'agents.create.localDescription': {
    defaultMessage: 'Paste the whole block into your coding assistant, or run it section by section in a terminal.',
    description: 'Instructions above the immutable local app setup command block.',
  },
  'agents.create.copySetup': {
    defaultMessage: 'Copy setup',
    description: 'Button that copies the complete immutable local app setup block.',
  },
  'agents.create.setupInstructions': {
    defaultMessage: 'Setup instructions',
    description: 'Human-readable label used in clipboard notifications for the local setup block.',
  },
  'agents.create.futureDeploys': {
    defaultMessage: 'Future deploys',
    description: 'Heading above the immutable command used for later app deployments.',
  },
  'agents.create.futureDeploysDescription': {
    defaultMessage: 'After `.airlock/local/agent.toml` contains the Airlock URL and app ID, deploy with no arguments.',
    description: 'Explanation of when the future deployment command can omit arguments. Keep the path unchanged.',
  },
  'agents.create.copyCommand': {
    defaultMessage: 'Copy command',
    description: 'Button that copies the immutable future deployment command.',
  },
  'agents.create.appName': {
    defaultMessage: 'App Name',
    description: 'Field label for the new app’s user-provided name.',
  },
  'agents.create.slug': {
    defaultMessage: 'Slug',
    description: 'Field label for an app’s URL-safe slug.',
  },
  'agents.create.slugHelp': {
    defaultMessage: 'URL-safe identifier, auto-generated from name.',
    description: 'Help text explaining the generated app slug.',
  },
  'agents.create.generateNotice': {
    defaultMessage: 'Airlock creates a new repo from your instructions, then opens the build page while it generates and compiles the first version.',
    description: 'Notice explaining what happens after generating an app from instructions.',
  },
  'agents.create.gitNotice': {
    defaultMessage: 'Airlock imports the selected branch and builds it as-is. Choose whether Airlock may push code changes, only follows Git, or copies the source once.',
    description: 'Notice explaining how Git import and source modes work.',
  },
  'agents.create.repoUrl': {
    defaultMessage: 'Repo URL',
    description: 'Field label for the Git repository URL imported during app creation.',
  },
  'agents.create.repoUrlPlaceholder': {
    defaultMessage: 'https://github.com/you/your-app.git',
    description: 'Example immutable Git repository URL. Do not translate or alter the URL.',
  },
  'agents.create.choosePat': {
    defaultMessage: 'Choose a PAT',
    description: 'Placeholder prompting the user to choose a Git personal access token.',
  },
  'agents.create.noCredentialsBeforeLink': {
    defaultMessage: 'No credentials yet -',
    description: 'Empty Git credential notice immediately before the settings link.',
  },
  'agents.create.addPatLink': {
    defaultMessage: 'add a PAT in Settings',
    description: 'Link text for adding a Git personal access token in settings.',
  },
  'agents.create.readOnlyHelp': {
    defaultMessage: 'Git always wins. Airlock polls and rebuilds this branch, but codegen, local deploys, and source rollbacks are disabled.',
    description: 'Help text for read-only Git source mode during app creation.',
  },
  'agents.create.importOnceHelp': {
    defaultMessage: 'The repository is copied once and then disconnected. Airlock-managed codegen and local deploys remain available.',
    description: 'Help text for one-time Git import source mode during app creation.',
  },
  'agents.create.otherCapabilityOverrides': {
    defaultMessage: 'Other capability overrides',
    description: 'Legend for optional app model capability overrides.',
  },
  'agents.create.changeRequest': {
    defaultMessage: 'Change request',
    description: 'Field label for source changes requested while importing an app.',
  },
  'agents.create.instructions': {
    defaultMessage: 'Instructions',
    description: 'Field label for instructions used to generate a new app.',
  },
  'agents.create.changeRequestPlaceholder': {
    defaultMessage: 'Example: Add a dashboard page for weekly presentation analytics.',
    description: 'Example change request for an imported app.',
  },
  'agents.create.instructionsPlaceholder': {
    defaultMessage: 'Describe what this app should do and what tools it needs, e.g. "Connect to Gmail and summarize my daily emails". Leave empty for a default app.',
    description: 'Prompt and example for app generation instructions. Keep the Gmail product name unchanged.',
  },
  'agents.create.changeRequestHelp': {
    defaultMessage: 'Airlock imports the repo first, then applies this request during the build.',
    description: 'Help text explaining when an imported app change request is applied.',
  },
  'agents.create.importAction': {
    defaultMessage: 'Import App',
    description: 'Primary action that imports and builds an app from Git.',
  },
  'agents.create.generateAction': {
    defaultMessage: 'Generate App',
    description: 'Primary action that generates and builds an app from instructions.',
  },
  'agents.create.buildingName': {
    defaultMessage: 'Building {name}…',
    description: 'Interim progress message while the named app’s build is starting. Preserve the app name.',
  },
  'agents.create.openingBuild': {
    defaultMessage: 'Opening the build view…',
    description: 'Interim progress message before navigating to the app build view.',
  },
  'agents.create.model.build': {
    defaultMessage: 'Build Model',
    description: 'Label for the language model used to generate app source.',
  },
  'agents.create.model.buildHelp': {
    defaultMessage: "Used by Sol to generate this app's code. Leave empty for Default.",
    description: 'Help text for the app build model override. Keep the Sol product name unchanged.',
  },
  'agents.create.model.execution': {
    defaultMessage: 'Execution Model',
    description: 'Label for the default language model used by the app at runtime.',
  },
  'agents.create.model.executionHelp': {
    defaultMessage: 'Runtime default for LLM calls. Leave empty for Default.',
    description: 'Help text for the app execution model override.',
  },
  'agents.create.model.vision': {
    defaultMessage: 'Vision',
    description: 'Label for the app vision model override.',
  },
  'agents.create.model.visionHelp': {
    defaultMessage: 'Image → text tasks.',
    description: 'Help text describing vision model tasks.',
  },
  'agents.create.model.stt': {
    defaultMessage: 'STT',
    description: 'Label for the app speech-to-text model override. Keep the standard acronym if appropriate.',
  },
  'agents.create.model.sttHelp': {
    defaultMessage: 'Speech-to-text transcription.',
    description: 'Help text describing the speech-to-text model capability.',
  },
  'agents.create.model.tts': {
    defaultMessage: 'TTS',
    description: 'Label for the app text-to-speech model override. Keep the standard acronym if appropriate.',
  },
  'agents.create.model.ttsHelp': {
    defaultMessage: 'Text-to-speech synthesis.',
    description: 'Help text describing the text-to-speech model capability.',
  },
  'agents.create.model.imageGen': {
    defaultMessage: 'Image Gen',
    description: 'Label for the app image generation model override.',
  },
  'agents.create.model.imageGenHelp': {
    defaultMessage: 'Text-to-image generation.',
    description: 'Help text describing the image generation model capability.',
  },
  'agents.create.model.embedding': {
    defaultMessage: 'Embedding',
    description: 'Label for the app embedding model override.',
  },
  'agents.create.model.embeddingHelp': {
    defaultMessage: 'Text → vector embeddings.',
    description: 'Help text describing the embedding model capability.',
  },
  'agents.create.model.webSearch': {
    defaultMessage: 'Web Search',
    description: 'Label for the app web search provider and model override.',
  },
  'agents.create.model.webSearchHelp': {
    defaultMessage: 'Web search backend + model. Pick "Provider default" to let the backend choose its model.',
    description: 'Help text for selecting an app web search provider and model.',
  },
  'agents.create.model.default': {
    defaultMessage: 'Default',
    description: 'Placeholder indicating that an app model uses the system default.',
  },
  'agents.create.model.defaultValue': {
    defaultMessage: 'Default ({model})',
    description: 'Placeholder showing the exact model name selected by the system default. Preserve the model name.',
  },
  'agents.create.builtSuccessfully': {
    defaultMessage: 'App built successfully',
    description: 'Toast confirming that initial app creation and build succeeded.',
  },
  'agents.create.buildFailedSentence': {
    defaultMessage: 'Build failed.',
    description: 'Fallback app creation build failure shown as a complete sentence.',
  },
  'agents.create.nameAndSlugRequired': {
    defaultMessage: 'Name and slug are required',
    description: 'Validation error shown when required app identity fields are empty.',
  },
  'agents.create.advancedOverridesNotSaved': {
    defaultMessage: 'App created - advanced model overrides not saved',
    description: 'Warning shown when app creation succeeds but optional model overrides fail to save.',
  },
  'agents.create.failed': {
    defaultMessage: 'Failed to create app',
    description: 'Fallback error shown when app creation fails.',
  },
  'agents.detail.nameRequired': {
    defaultMessage: 'Name is required',
    description: 'Validation error shown when an app rename or clone name is empty.',
  },
  'agents.detail.invalidSlug': {
    defaultMessage: 'Invalid slug',
    description: 'Validation error heading shown for an invalid app slug.',
  },
  'agents.detail.invalidSlugDetailRename': {
    defaultMessage: '2–63 chars: lowercase letters/digits, single dashes between.',
    description: 'Detailed app slug validation requirements in the rename flow.',
  },
  'agents.detail.invalidSlugDetailClone': {
    defaultMessage: '2–63 chars: lowercase letters/digits, single dashes.',
    description: 'Detailed app slug validation requirements in the clone flow.',
  },
  'agents.detail.renamed': {
    defaultMessage: 'App renamed',
    description: 'Toast confirming an app was renamed.',
  },
  'agents.detail.slugTaken': {
    defaultMessage: 'Slug already taken',
    description: 'Error shown when another app already uses the requested slug.',
  },
  'agents.detail.renameFailed': {
    defaultMessage: 'Rename failed',
    description: 'Fallback error shown when renaming an app fails.',
  },
  'agents.detail.copyName': {
    defaultMessage: '{name} copy',
    description: 'Default name for a cloned app. Preserve the original app name.',
  },
  'agents.detail.cloned': {
    defaultMessage: 'App cloned',
    description: 'Toast confirming that an app clone was created.',
  },
  'agents.detail.buildingCopy': {
    defaultMessage: 'Building your copy…',
    description: 'Toast detail explaining that the newly cloned app is building.',
  },
  'agents.detail.cloneFailed': {
    defaultMessage: 'Clone failed',
    description: 'Fallback error shown when cloning an app fails.',
  },
  'agents.detail.pickTransferUser': {
    defaultMessage: 'Pick a user to transfer to',
    description: 'Validation warning shown when no new app owner is selected.',
  },
  'agents.detail.transferConfirm': {
    defaultMessage: 'Transfer "{name}" to {user}? You will lose access, and its connections, git credential, and bridges will be unbound.',
    description: 'Confirmation before transferring app ownership. Preserve the app name and selected user label.',
  },
  'agents.detail.thisUser': {
    defaultMessage: 'this user',
    description: 'Fallback label for the selected new app owner when no user label is available.',
  },
  'agents.detail.transferOwnership': {
    defaultMessage: 'Transfer ownership',
    description: 'App action and dialog heading for transferring ownership to another user.',
  },
  'agents.detail.ownershipTransferred': {
    defaultMessage: 'Ownership transferred',
    description: 'Toast confirming app ownership was transferred.',
  },
  'agents.detail.transferFailed': {
    defaultMessage: 'Transfer failed',
    description: 'Fallback error shown when transferring app ownership fails.',
  },
  'agents.detail.section.members': {
    defaultMessage: 'Members',
    description: 'App detail navigation section for app members.',
  },
  'agents.detail.section.connections': {
    defaultMessage: 'Connections',
    description: 'App detail navigation section for external connections.',
  },
  'agents.detail.section.mcpServers': {
    defaultMessage: 'MCP Servers',
    description: 'App detail navigation section for MCP servers. Keep the MCP acronym unchanged.',
  },
  'agents.detail.section.connectors': {
    defaultMessage: 'Connectors',
    description: 'App detail navigation section for connectors.',
  },
  'agents.detail.section.environment': {
    defaultMessage: 'Environment',
    description: 'App detail navigation section for environment variables.',
  },
  'agents.detail.section.webhooks': {
    defaultMessage: 'Webhooks',
    description: 'App detail navigation section for webhooks.',
  },
  'agents.detail.section.schedules': {
    defaultMessage: 'Schedules',
    description: 'App detail navigation section for schedules.',
  },
  'agents.detail.section.siblings': {
    defaultMessage: 'Siblings',
    description: 'App detail navigation section for sibling app relationships.',
  },
  'agents.detail.section.access': {
    defaultMessage: 'Access',
    description: 'App detail navigation section for access settings.',
  },
  'agents.detail.section.source': {
    defaultMessage: 'Source',
    description: 'App detail navigation section for source and Git configuration.',
  },
  'agents.detail.section.routes': {
    defaultMessage: 'Routes',
    description: 'App detail navigation section for HTTP routes.',
  },
  'agents.detail.section.tools': {
    defaultMessage: 'Tools',
    description: 'App detail navigation section for app tools.',
  },
  'agents.detail.section.models': {
    defaultMessage: 'Models',
    description: 'App detail navigation section for model configuration.',
  },
  'agents.detail.needsSetupCount': {
    defaultMessage: '{formattedCount} needs setup | {formattedCount} need setup',
    description: 'Pluralized count of app resources that still require setup. {count} selects the plural form; {formattedCount} is locale-formatted.',
  },
  'agents.detail.statusTooltip.running': {
    defaultMessage: 'A container is live',
    description: 'Tooltip explaining the running app lifecycle state.',
  },
  'agents.detail.statusTooltip.suspended': {
    defaultMessage: 'No container running - starts automatically on next use',
    description: 'Tooltip explaining the suspended app lifecycle state.',
  },
  'agents.detail.statusTooltip.stopped': {
    defaultMessage: 'Stopped - will not auto-resume; click Start',
    description: 'Tooltip explaining the stopped app lifecycle state and how to restart it.',
  },
  'agents.detail.notFound': {
    defaultMessage: 'App not found',
    description: 'Error shown when the requested app does not exist or is inaccessible.',
  },
  'agents.detail.buildComplete': {
    defaultMessage: 'Build complete',
    description: 'Toast confirming an app build completed.',
  },
  'agents.detail.buildFailed': {
    defaultMessage: 'Build failed',
    description: 'Fallback error shown when an app build fails.',
  },
  'agents.detail.buildCancelled': {
    defaultMessage: 'Build cancelled',
    description: 'Toast confirming an app build was cancelled.',
  },
  'agents.detail.requestDeclined': {
    defaultMessage: 'Request declined',
    description: 'Toast heading shown when the app builder declines a change request.',
  },
  'agents.detail.outsideBuilderScope': {
    defaultMessage: "Outside the app builder's scope",
    description: 'Fallback explanation shown when a request is outside the app builder’s scope.',
  },
  'agents.detail.synced': {
    defaultMessage: 'Synced',
    description: 'Toast heading confirming an app synchronized its declared capabilities.',
  },
  'agents.detail.appSynced': {
    defaultMessage: '{name} synced',
    description: 'Toast detail confirming the named app or slug synchronized. Preserve the interpolated name.',
  },
  'agents.detail.appFallback': {
    defaultMessage: 'App',
    description: 'Fallback app name used in a synchronization notification.',
  },
  'agents.detail.stopConfirm': {
    defaultMessage: 'Stop app "{name}"? It will not auto-resume on the next trigger - you\'ll have to click Start to bring it back.',
    description: 'Confirmation before stopping the named app. Preserve the app name.',
  },
  'agents.detail.stopTitle': {
    defaultMessage: 'Confirm Stop',
    description: 'Heading for the app stop confirmation dialog.',
  },
  'agents.detail.stopped': {
    defaultMessage: 'App stopped',
    description: 'Toast confirming an app was stopped.',
  },
  'agents.detail.stopFailed': {
    defaultMessage: 'Stop failed',
    description: 'Fallback error shown when stopping an app fails.',
  },
  'agents.detail.suspended': {
    defaultMessage: 'App suspended',
    description: 'Toast confirming a running app was suspended.',
  },
  'agents.detail.suspendedDetail': {
    defaultMessage: 'Auto-resumes on the next trigger.',
    description: 'Toast detail explaining when a suspended app resumes.',
  },
  'agents.detail.suspendFailed': {
    defaultMessage: 'Suspend failed',
    description: 'Fallback error shown when suspending an app fails.',
  },
  'agents.detail.started': {
    defaultMessage: 'App started',
    description: 'Toast confirming an app was started.',
  },
  'agents.detail.startFailed': {
    defaultMessage: 'Start failed',
    description: 'Fallback error shown when starting an app fails.',
  },
  'agents.detail.deleteConfirm': {
    defaultMessage: 'Delete app "{name}"? This cannot be undone.',
    description: 'Confirmation before permanently deleting the named app. Preserve the app name.',
  },
  'agents.detail.deleteTitle': {
    defaultMessage: 'Confirm Delete',
    description: 'Heading for the app deletion confirmation dialog.',
  },
  'agents.detail.deleted': {
    defaultMessage: 'App deleted',
    description: 'Toast confirming an app was permanently deleted.',
  },
  'agents.detail.deleteFailed': {
    defaultMessage: 'Delete failed',
    description: 'Fallback error shown when deleting an app fails.',
  },
  'agents.detail.rebuildQueued': {
    defaultMessage: 'Rebuild queued',
    description: 'Toast confirming an app rebuild was queued.',
  },
  'agents.detail.upgradeQueued': {
    defaultMessage: 'Upgrade queued',
    description: 'Toast confirming an app upgrade was queued.',
  },
  'agents.detail.rebuildFailed': {
    defaultMessage: 'Rebuild failed',
    description: 'Fallback error shown when queuing an app rebuild fails.',
  },
  'agents.detail.upgradeFailed': {
    defaultMessage: 'Upgrade failed',
    description: 'Fallback error shown when queuing an app upgrade fails.',
  },
  'agents.detail.cancelFailed': {
    defaultMessage: 'Cancel failed',
    description: 'Fallback error shown when cancelling an app build fails.',
  },
  'agents.detail.renameAria': {
    defaultMessage: 'Rename app',
    description: 'Accessible label for the icon button that renames an app.',
  },
  'agents.detail.needsSetupBadge': {
    defaultMessage: 'Needs setup ({formattedCount})',
    description: 'App header badge showing the locale-formatted number of resources requiring setup. {count} is the numeric count.',
  },
  'agents.detail.chat': {
    defaultMessage: 'Chat',
    description: 'Button opening a chat with the app.',
  },
  'agents.detail.web': {
    defaultMessage: 'Web',
    description: 'Button opening the app’s web homepage.',
  },
  'agents.detail.actions': {
    defaultMessage: 'Actions',
    description: 'Label for app lifecycle and administration actions.',
  },
  'agents.detail.cancelBuild': {
    defaultMessage: 'Cancel Build',
    description: 'Button that cancels the app build currently in progress.',
  },
  'agents.detail.sectionNavigation': {
    defaultMessage: 'Section navigation',
    description: 'Accessible label for navigation among app detail sections.',
  },
  'agents.detail.activity': {
    defaultMessage: 'Activity',
    description: 'App detail section containing runs, builds, and jobs.',
  },
  'agents.detail.runs': {
    defaultMessage: 'Runs',
    description: 'Tab listing app runs in the Activity section.',
  },
  'agents.detail.builds': {
    defaultMessage: 'Builds',
    description: 'Tab listing app builds in the Activity section.',
  },
  'agents.detail.jobs': {
    defaultMessage: 'Jobs',
    description: 'Tab listing app jobs in the Activity section.',
  },
  'agents.detail.rebuildApp': {
    defaultMessage: 'Rebuild App',
    description: 'Heading for the dialog that rebuilds an app without source changes.',
  },
  'agents.detail.upgradeApp': {
    defaultMessage: 'Upgrade App',
    description: 'Heading for the dialog that requests source changes and rebuilds an app.',
  },
  'agents.detail.rebuildDescription': {
    defaultMessage: 'Pull the latest commit from the configured Git branch and rebuild it against the current agentsdk.',
    description: 'Explanation of rebuilding an app whose Git source is authoritative. Keep agentsdk unchanged.',
  },
  'agents.detail.gitAuthoritative': {
    defaultMessage: 'Git remains authoritative. Airlock will not change or push source code.',
    description: 'Reminder shown before rebuilding an app in read-only Git mode.',
  },
  'agents.detail.upgradePrompt': {
    defaultMessage: 'Describe what to change or fix:',
    description: 'Prompt for an app upgrade change request.',
  },
  'agents.detail.upgradePlaceholder': {
    defaultMessage: 'e.g. Add a /history page that shows past voting rounds',
    description: 'Example app upgrade request. Keep the /history path unchanged.',
  },
  'agents.detail.emptyUpgradeBeforeRebuild': {
    defaultMessage: 'Leave empty to',
    description: 'Upgrade help text immediately before the emphasized rebuild action.',
  },
  'agents.detail.emptyUpgradeAfterRebuild': {
    defaultMessage: 'against the latest agentsdk - no code changes. If the SDK API changed and the code no longer compiles, the rebuild fails; add a description so the builder can adapt it.',
    description: 'Upgrade help text after the emphasized rebuild action. Keep agentsdk and SDK unchanged.',
  },
  'agents.detail.renameTitle': {
    defaultMessage: 'Rename app',
    description: 'Heading for the dialog that changes an app name or slug.',
  },
  'agents.detail.name': {
    defaultMessage: 'Name',
    description: 'Field label for an app name in rename and clone dialogs.',
  },
  'agents.detail.slugHelp': {
    defaultMessage: 'Lowercase letters, digits and single dashes (2–63 chars).',
    description: 'Help text listing valid app slug characters and length.',
  },
  'agents.detail.slugWarningBeforeBinding': {
    defaultMessage: 'Changing the slug re-points sibling',
    description: 'Slug change warning immediately before the immutable agent_<slug> binding pattern.',
  },
  'agents.detail.slugWarningAfterBinding': {
    defaultMessage: 'bindings and breaks any externally-configured MCP URL using the old slug. In-app links keep working.',
    description: 'Slug change warning after the immutable binding pattern. Keep MCP unchanged.',
  },
  'agents.detail.cloneTitle': {
    defaultMessage: 'Clone app',
    description: 'Heading for the dialog that clones an app.',
  },
  'agents.detail.cloneDescriptionBeforeNot': {
    defaultMessage: "Copies this app's code and settings into a new app you own. Its data, secrets, connections and bridges are",
    description: 'Clone explanation immediately before the emphasized word “not”.',
  },
  'agents.detail.not': {
    defaultMessage: 'not',
    description: 'Emphasized negation in the explanation of data excluded from an app clone.',
  },
  'agents.detail.cloneDescriptionAfterNot': {
    defaultMessage: 'copied - the clone starts clean and builds fresh.',
    description: 'Clone explanation after the emphasized word “not”.',
  },
  'agents.detail.transferDescription': {
    defaultMessage: 'The new owner becomes admin and you lose access. Owner-scoped bindings (connections, MCP server credentials, git credential, bridges) are unbound - the new owner reconnects their own.',
    description: 'Warning explaining access and binding changes caused by transferring app ownership. Keep MCP unchanged.',
  },
  'agents.detail.transferTo': {
    defaultMessage: 'Transfer to',
    description: 'Field label for selecting the new app owner.',
  },
  'agents.detail.selectUser': {
    defaultMessage: 'Select a user',
    description: 'Placeholder for selecting the new app owner.',
  },
})
