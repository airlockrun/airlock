import { defineMessages } from './define'

export const administrationMessages = defineMessages({
  'administration.action.cancel': {
    defaultMessage: 'Cancel',
    description: 'Button that closes an administration dialog without saving changes.',
  },
  'administration.action.create': {
    defaultMessage: 'Create',
    description: 'Button that creates an administration resource.',
  },
  'administration.action.disable': {
    defaultMessage: 'Disable',
    description: 'Confirmation button that disables a model or provider.',
  },
  'administration.action.done': {
    defaultMessage: 'Done',
    description: 'Button that closes a completed administration workflow.',
  },
  'administration.action.save': {
    defaultMessage: 'Save',
    description: 'Button that saves administration settings.',
  },
  'administration.action.update': {
    defaultMessage: 'Update',
    description: 'Button that updates an administration resource.',
  },
  'administration.capability.embedding': {
    defaultMessage: 'Embedding',
    description: 'Display label for the model capability that creates vector embeddings.',
  },
  'administration.capability.file': {
    defaultMessage: 'File',
    description: 'Display label for the model capability that accepts files.',
  },
  'administration.capability.image': {
    defaultMessage: 'Image',
    description: 'Display label for the model capability that processes or produces images.',
  },
  'administration.capability.imageGeneration': {
    defaultMessage: 'Image gen',
    description: 'Short display label for the model capability that generates images.',
  },
  'administration.capability.reasoning': {
    defaultMessage: 'reasoning',
    description: 'Lowercase badge label indicating that a model supports reasoning.',
  },
  'administration.capability.reranking': {
    defaultMessage: 'Reranking',
    description: 'Display label for the model capability that reranks search results.',
  },
  'administration.capability.search': {
    defaultMessage: 'Web search',
    description: 'Display label for the model capability that performs live web searches.',
  },
  'administration.capability.speech': {
    defaultMessage: 'Speech',
    description: 'Display label for the text-to-speech model capability.',
  },
  'administration.capability.text': {
    defaultMessage: 'Text',
    description: 'Display label for the text language-model capability.',
  },
  'administration.capability.tools': {
    defaultMessage: 'tools',
    description: 'Lowercase badge label indicating that a model supports tool calls.',
  },
  'administration.capability.transcription': {
    defaultMessage: 'Transcription',
    description: 'Display label for the speech-to-text model capability.',
  },
  'administration.capability.video': {
    defaultMessage: 'Video',
    description: 'Display label for the model capability that processes video.',
  },
  'administration.capability.vision': {
    defaultMessage: 'Vision',
    description: 'Display label for the model capability that reads images.',
  },
  'administration.locale.english': {
    defaultMessage: 'English',
    description: 'Name of the English language in the interface language selector.',
  },
  'administration.locale.russian': {
    defaultMessage: 'Russian',
    description: 'Name of the Russian language in the interface language selector.',
  },
  'administration.models.allowedCount': {
    defaultMessage: '{formattedCount} allowed',
    description: 'Badge showing the locale-formatted number of provider-model combinations allowed in the workspace. {count} is the numeric count.',
  },
  'administration.models.allowedHeader': {
    defaultMessage: 'Allowed',
    description: 'Table column heading for the switch that controls whether a model is allowed.',
  },
  'administration.models.capabilitiesHeader': {
    defaultMessage: 'Capabilities',
    description: 'Table column heading for model capability badges.',
  },
  'administration.models.description': {
    defaultMessage: 'Models are deny-by-default: an app can only be assigned a model you allow here. Your configured default models are always usable regardless of this list. Allowing a model makes it available to everyone in this workspace.',
    description: 'Explanation of workspace model allow-list behavior.',
  },
  'administration.models.disableConfirm': {
    defaultMessage: '{formattedCount} app uses this model as a configured override. Disabling it will reset it to the workspace default. Continue? | {formattedCount} apps use this model as a configured override. Disabling it will reset them to the workspace default. Continue?',
    description: 'Confirmation shown before disabling a model used as an app override. {count} selects the plural form; {formattedCount} is locale-formatted.',
  },
  'administration.models.disableTitle': {
    defaultMessage: 'Disable model',
    description: 'Title of the confirmation dialog for disabling an allowed model.',
  },
  'administration.models.emptyBeforeLink': {
    defaultMessage: 'No configured providers with models. Add a provider on the',
    description: 'First part of an empty-state sentence before a link to the Providers page.',
  },
  'administration.models.emptyLink': {
    defaultMessage: 'Providers',
    description: 'Link text for the Providers administration page in the models empty state.',
  },
  'administration.models.emptyAfterLink': {
    defaultMessage: 'page first.',
    description: 'Final part of an empty-state sentence after a link to the Providers page.',
  },
  'administration.models.inputPrice': {
    defaultMessage: 'in',
    description: 'Short label for a model input-token price.',
  },
  'administration.models.modelHeader': {
    defaultMessage: 'Model',
    description: 'Table column heading for a model name and ID.',
  },
  'administration.models.outputPrice': {
    defaultMessage: 'out',
    description: 'Short label for a model output-token price.',
  },
  'administration.models.priceHeader': {
    defaultMessage: 'Price /1M',
    description: 'Table column heading for model prices per one million tokens.',
  },
  'administration.models.searchPlaceholder': {
    defaultMessage: 'Filter by name or capability (e.g. transcription, vision)',
    description: 'Placeholder for filtering models by name, ID, or capability.',
  },
  'administration.models.title': {
    defaultMessage: 'Allowed models',
    description: 'Page title for workspace model allow-list administration.',
  },
  'administration.models.updateFailed': {
    defaultMessage: 'Update failed',
    description: 'Fallback error shown when changing whether a model is allowed fails.',
  },
  'administration.providerModels.capability.includeUsage': {
    defaultMessage: 'Include usage',
    description: 'Toggle label for requesting usage data from an OpenAI-compatible model endpoint.',
  },
  'administration.providerModels.capability.reasoning': {
    defaultMessage: 'Reasoning',
    description: 'Toggle label for confirming that an endpoint model supports reasoning.',
  },
  'administration.providerModels.capability.structuredOutputs': {
    defaultMessage: 'Structured outputs',
    description: 'Toggle label for confirming that an endpoint model supports structured outputs.',
  },
  'administration.providerModels.capability.toolCalls': {
    defaultMessage: 'Tool calls',
    description: 'Toggle label for confirming that an endpoint model supports tool calls.',
  },
  'administration.providerModels.capability.vision': {
    defaultMessage: 'Vision',
    description: 'Toggle label for confirming that an endpoint model supports vision.',
  },
  'administration.providerModels.confirm': {
    defaultMessage: 'Confirm',
    description: 'Checkbox label for including a discovered endpoint model in the confirmed model list.',
  },
  'administration.providerModels.contextLimit': {
    defaultMessage: 'Context limit',
    description: 'Field label for an endpoint model context-token limit.',
  },
  'administration.providerModels.discover': {
    defaultMessage: 'Discover models',
    description: 'Button that asks an OpenAI-compatible endpoint for its model IDs.',
  },
  'administration.providerModels.discovered': {
    defaultMessage: 'Discovered',
    description: 'State badge for an endpoint model found by discovery but not saved.',
  },
  'administration.providerModels.discoveryComplete': {
    defaultMessage: 'Discovery complete',
    description: 'Toast title shown after endpoint model discovery succeeds.',
  },
  'administration.providerModels.discoveryFailed': {
    defaultMessage: 'Discovery failed',
    description: 'Toast title shown after endpoint model discovery fails.',
  },
  'administration.providerModels.discoveryFailedFallback': {
    defaultMessage: 'Model discovery failed.',
    description: 'Fallback error detail shown when endpoint model discovery fails.',
  },
  'administration.providerModels.discoveryHelp': {
    defaultMessage: 'Discovery only reads model IDs from the endpoint. Select models and review their conservative defaults, then use Save models to replace the confirmed list.',
    description: 'Explanation of endpoint model discovery and confirmation behavior.',
  },
  'administration.providerModels.displayName': {
    defaultMessage: 'Display name',
    description: 'Field label for an endpoint model display name.',
  },
  'administration.providerModels.empty': {
    defaultMessage: 'No confirmed models. Discover endpoint models, or save this empty list.',
    description: 'Empty state in the endpoint model confirmation dialog.',
  },
  'administration.providerModels.loadFailed': {
    defaultMessage: 'Failed to load confirmed models.',
    description: 'Fallback error shown when confirmed endpoint models cannot be loaded.',
  },
  'administration.providerModels.models': {
    defaultMessage: 'Models',
    description: 'Fallback title of the endpoint models dialog when no provider is available.',
  },
  'administration.providerModels.modelsFor': {
    defaultMessage: 'Models for {provider}',
    description: 'Endpoint models dialog title. Provider is the configured provider display name or slug and must not be translated.',
  },
  'administration.providerModels.newModels': {
    defaultMessage: '{formattedCount} new model available to confirm. | {formattedCount} new models available to confirm.',
    description: 'Model discovery result detail. {count} selects the plural form; {formattedCount} is locale-formatted.',
  },
  'administration.providerModels.noNewModels': {
    defaultMessage: 'No new model IDs were reported.',
    description: 'Model discovery result when the endpoint reports no unknown model IDs.',
  },
  'administration.providerModels.outputLimit': {
    defaultMessage: 'Output limit',
    description: 'Field label for an endpoint model output-token limit.',
  },
  'administration.providerModels.removeAria': {
    defaultMessage: 'Remove model',
    description: 'Accessible label for a button that removes a model from the endpoint model draft.',
  },
  'administration.providerModels.save': {
    defaultMessage: 'Save models',
    description: 'Button that replaces the confirmed endpoint model list.',
  },
  'administration.providerModels.saveFailed': {
    defaultMessage: 'Save failed',
    description: 'Toast title shown when confirmed endpoint models cannot be saved.',
  },
  'administration.providerModels.saveFailedFallback': {
    defaultMessage: 'Failed to save confirmed models.',
    description: 'Fallback error detail shown when confirmed endpoint models cannot be saved.',
  },
  'administration.providerModels.saved': {
    defaultMessage: 'Saved',
    description: 'State badge for an endpoint model already in the saved confirmed list.',
  },
  'administration.providerModels.savedToast': {
    defaultMessage: 'Confirmed models saved',
    description: 'Success toast shown after replacing the confirmed endpoint model list.',
  },
  'administration.providerModels.selectedCount': {
    defaultMessage: '{formattedCount} model selected | {formattedCount} models selected',
    description: 'Footer count of endpoint models selected for confirmation. {count} selects the plural form; {formattedCount} is locale-formatted.',
  },
  'administration.providers.action.add': {
    defaultMessage: 'Add Provider',
    description: 'Button and dialog title for adding a configured model provider.',
  },
  'administration.providers.action.addCapability': {
    defaultMessage: 'Add {capability}',
    description: 'Button for adding a provider that supplies a missing capability.',
  },
  'administration.providers.action.deleteAria': {
    defaultMessage: 'Delete provider',
    description: 'Accessible label for a button that deletes a configured provider.',
  },
  'administration.providers.action.editAria': {
    defaultMessage: 'Edit provider',
    description: 'Accessible label for a button that edits a configured provider.',
  },
  'administration.providers.action.editTitle': {
    defaultMessage: 'Edit Provider',
    description: 'Title of the configured provider editing dialog.',
  },
  'administration.providers.action.models': {
    defaultMessage: 'Models',
    description: 'Button that opens the confirmed models dialog for an OpenAI-compatible provider.',
  },
  'administration.providers.apiKey': {
    defaultMessage: 'API Key',
    description: 'Field label for a provider API key when creating a hosted provider.',
  },
  'administration.providers.apiKeyKeepCurrent': {
    defaultMessage: 'API Key (leave blank to keep current)',
    description: 'Provider API key field label while editing an existing provider.',
  },
  'administration.providers.apiKeyOptional': {
    defaultMessage: 'API Key (optional)',
    description: 'Provider API key field label for a local OpenAI-compatible endpoint.',
  },
  'administration.providers.apiKeyRequired': {
    defaultMessage: 'Hosted providers require an API key.',
    description: 'Validation message for a missing hosted-provider API key.',
  },
  'administration.providers.baseURL': {
    defaultMessage: 'Base URL',
    description: 'Table heading and required field label for a provider base URL.',
  },
  'administration.providers.baseURLOptional': {
    defaultMessage: 'Base URL (optional)',
    description: 'Field label for an optional hosted-provider base URL.',
  },
  'administration.providers.baseURLDefaultHelp': {
    defaultMessage: 'Leave blank for the provider default.',
    description: 'Help text for an optional hosted-provider base URL.',
  },
  'administration.providers.baseURLInvalid': {
    defaultMessage: 'Enter an absolute HTTP(S) URL without credentials, query, or fragment.',
    description: 'Validation message for an invalid provider base URL.',
  },
  'administration.providers.capabilitiesSubtitle': {
    defaultMessage: 'What your configured providers can do. Click Add on any missing capability to discover providers that supply it.',
    description: 'Explanation shown above the configured-provider capability matrix.',
  },
  'administration.providers.capabilitiesTitle': {
    defaultMessage: 'Capabilities',
    description: 'Title of the configured-provider capability matrix.',
  },
  'administration.providers.checkDetails': {
    defaultMessage: 'Check the provider details',
    description: 'Error toast shown when the configured-provider form is invalid.',
  },
  'administration.providers.confirmDelete': {
    defaultMessage: 'Delete provider "{provider}"? This cannot be undone.',
    description: 'Confirmation before deleting a provider. Provider is its display name and must not be translated.',
  },
  'administration.providers.confirmDeleteTitle': {
    defaultMessage: 'Confirm Delete',
    description: 'Title of a destructive administration confirmation dialog.',
  },
  'administration.providers.confirmDisable': {
    defaultMessage: 'Disable provider "{provider}"? Apps using it will be unable to make new model requests until it is enabled again.',
    description: 'Confirmation before disabling a provider. Provider is its display name or slug and must not be translated.',
  },
  'administration.providers.confirmDisableTitle': {
    defaultMessage: 'Disable Provider',
    description: 'Title of the confirmation dialog for disabling a configured provider.',
  },
  'administration.providers.created': {
    defaultMessage: 'Provider created',
    description: 'Success toast shown after creating a configured provider.',
  },
  'administration.providers.creationHosted': {
    defaultMessage: 'Hosted provider',
    description: 'Provider creation path for a hosted provider service.',
  },
  'administration.providers.creationLocal': {
    defaultMessage: 'Local / OpenAI-compatible',
    description: 'Provider creation path for a local or OpenAI-compatible endpoint.',
  },
  'administration.providers.customPreset': {
    defaultMessage: 'Custom',
    description: 'Endpoint preset option for manually entering a custom local endpoint.',
  },
  'administration.providers.deleteFailed': {
    defaultMessage: 'Delete failed',
    description: 'Fallback error shown when deleting a configured provider fails.',
  },
  'administration.providers.deleted': {
    defaultMessage: 'Provider deleted',
    description: 'Success toast shown after deleting a configured provider.',
  },
  'administration.providers.disabled': {
    defaultMessage: 'Disabled',
    description: 'State label for a disabled configured provider.',
  },
  'administration.providers.disabledToast': {
    defaultMessage: 'Provider disabled',
    description: 'Success toast shown after disabling a configured provider.',
  },
  'administration.providers.disableFailed': {
    defaultMessage: 'Provider could not be disabled',
    description: 'Error toast title shown when disabling a configured provider fails.',
  },
  'administration.providers.enabled': {
    defaultMessage: 'Enabled',
    description: 'State label for an enabled configured provider.',
  },
  'administration.providers.enabledToast': {
    defaultMessage: 'Provider enabled',
    description: 'Success toast shown after enabling a configured provider.',
  },
  'administration.providers.enableFailed': {
    defaultMessage: 'Provider could not be enabled',
    description: 'Error toast title shown when enabling a configured provider fails.',
  },
  'administration.providers.endpointPreset': {
    defaultMessage: 'Endpoint preset',
    description: 'Field label for selecting a local model endpoint preset.',
  },
  'administration.providers.endpointPresetHelp': {
    defaultMessage: 'Presets only fill this form. You can edit every value before creating the provider.',
    description: 'Help text explaining that local endpoint presets do not lock form values.',
  },
  'administration.providers.localEndpointName': {
    defaultMessage: 'Local model endpoint',
    description: 'Suggested provider display name for a custom local model endpoint.',
  },
  'administration.providers.localURLHelp': {
    defaultMessage: 'The URL must be reachable from the Airlock server or container and include the OpenAI-compatible API root, usually /v1.',
    description: 'Network and URL guidance for a local OpenAI-compatible endpoint. Keep /v1 unchanged.',
  },
  'administration.providers.localURLRequired': {
    defaultMessage: 'A reachable API root URL is required.',
    description: 'Validation message for a missing local endpoint URL.',
  },
  'administration.providers.name': {
    defaultMessage: 'Provider',
    description: 'Table heading and field label for a model provider.',
  },
  'administration.providers.noProviders': {
    defaultMessage: 'No providers configured yet.',
    description: 'Empty state for the configured providers table.',
  },
  'administration.providers.notAvailable': {
    defaultMessage: 'Not available',
    description: 'Capability matrix state when no enabled provider supplies a capability.',
  },
  'administration.providers.operationFailed': {
    defaultMessage: 'Operation failed',
    description: 'Fallback error shown when creating or updating a configured provider fails.',
  },
  'administration.providers.providerDefault': {
    defaultMessage: 'Provider default',
    description: 'Label shown when a provider uses its built-in base URL or default model.',
  },
  'administration.providers.showAll': {
    defaultMessage: 'Show all',
    description: 'Link that removes a provider capability filter.',
  },
  'administration.providers.showingCapability': {
    defaultMessage: 'Showing providers that supply {capability}.',
    description: 'Notice that the provider picker is filtered to a capability.',
  },
  'administration.providers.slug': {
    defaultMessage: 'Slug',
    description: 'Field label for the URL-safe configured-provider slug.',
  },
  'administration.providers.slugHelp': {
    defaultMessage: 'Unique within this provider type. Suggested automatically; manual edits are preserved.',
    description: 'Help text explaining configured-provider slug uniqueness and suggestions.',
  },
  'administration.providers.slugInvalid': {
    defaultMessage: 'Use 1-63 lowercase letters, numbers, and single hyphens.',
    description: 'Validation message describing the configured-provider slug format.',
  },
  'administration.providers.status': {
    defaultMessage: 'Status',
    description: 'Table heading for configured-provider enabled status.',
  },
  'administration.providers.statusUpdateFailed': {
    defaultMessage: 'Status update failed',
    description: 'Fallback error detail shown when changing configured-provider status fails.',
  },
  'administration.providers.title': {
    defaultMessage: 'Providers',
    description: 'Page title for configured model provider administration.',
  },
  'administration.providers.updated': {
    defaultMessage: 'Provider updated',
    description: 'Success toast shown after updating a configured provider.',
  },
  'administration.providers.displayName': {
    defaultMessage: 'Display Name',
    description: 'Field label and table heading for a provider or user display name.',
  },
  'administration.providers.displayNameRequired': {
    defaultMessage: 'Enter a display name.',
    description: 'Validation message for a missing provider display name.',
  },
  'administration.providers.actions': {
    defaultMessage: 'Actions',
    description: 'Table heading for provider or user row actions.',
  },
  'administration.settings.buildHelp': {
    defaultMessage: 'Used by Sol for app code generation and upgrades.',
    description: 'Help text for the default build model setting.',
  },
  'administration.settings.buildLabel': {
    defaultMessage: 'Build Model',
    description: 'Label for the default model used to build app code.',
  },
  'administration.settings.buildPlaceholder': {
    defaultMessage: 'Select default build model',
    description: 'Placeholder for selecting the default build model.',
  },
  'administration.settings.embeddingHelp': {
    defaultMessage: 'Default model for text → vector embeddings (e.g. OpenAI text-embedding-3-small).',
    description: 'Help text for the default embedding model. Keep the example model ID unchanged.',
  },
  'administration.settings.embeddingPlaceholder': {
    defaultMessage: 'Select embedding model',
    description: 'Placeholder for selecting the default embedding model.',
  },
  'administration.settings.executionHelp': {
    defaultMessage: 'Runtime default when apps make language-model calls.',
    description: 'Help text for the default execution language model.',
  },
  'administration.settings.executionLabel': {
    defaultMessage: 'Execution Model (Text)',
    description: 'Label for the default text model used by apps at runtime.',
  },
  'administration.settings.executionPlaceholder': {
    defaultMessage: 'Select default execution model',
    description: 'Placeholder for selecting the default execution model.',
  },
  'administration.settings.failed': {
    defaultMessage: 'Failed',
    description: 'Fallback error toast shown when system settings cannot be saved.',
  },
  'administration.settings.imageGenerationHelp': {
    defaultMessage: 'Default model for text → image generation.',
    description: 'Help text for the default image-generation model.',
  },
  'administration.settings.imageGenerationLabel': {
    defaultMessage: 'Image Gen',
    description: 'Label for the default image-generation model setting.',
  },
  'administration.settings.imageGenerationPlaceholder': {
    defaultMessage: 'Select image-generation model',
    description: 'Placeholder for selecting the default image-generation model.',
  },
  'administration.settings.interfaceLanguage': {
    defaultMessage: 'Interface Language',
    description: 'Label for the system-wide interface language selector.',
  },
  'administration.settings.interfaceLanguageHelp': {
    defaultMessage: 'Used system-wide for the interface and generated responses.',
    description: 'Help text describing the scope of the interface language setting.',
  },
  'administration.settings.saved': {
    defaultMessage: 'Settings saved',
    description: 'Success toast shown after saving system settings.',
  },
  'administration.settings.searchHelp': {
    defaultMessage: 'Default web search backend + model. Only tool-capable text models are listed (the backend runs search by calling the model with a search tool). Pick "Provider default" to let the backend choose its model.',
    description: 'Help text for the default web search backend and model. "Provider default" is an option label.',
  },
  'administration.settings.searchLabel': {
    defaultMessage: 'Web Search',
    description: 'Label for the default web search backend and model setting.',
  },
  'administration.settings.searchPlaceholder': {
    defaultMessage: 'Select search backend',
    description: 'Placeholder for selecting the default web search backend.',
  },
  'administration.settings.speechHelp': {
    defaultMessage: 'Default model for text → speech synthesis.',
    description: 'Help text for the default text-to-speech model.',
  },
  'administration.settings.speechLabel': {
    defaultMessage: 'TTS',
    description: 'Short label for the default text-to-speech model setting.',
  },
  'administration.settings.speechPlaceholder': {
    defaultMessage: 'Select text-to-speech model',
    description: 'Placeholder for selecting the default text-to-speech model.',
  },
  'administration.settings.subtitle': {
    defaultMessage: 'Interface language and per-capability model defaults.',
    description: 'Subtitle of the system settings card.',
  },
  'administration.settings.systemSettings': {
    defaultMessage: 'System Settings',
    description: 'Title of the card containing system-wide settings.',
  },
  'administration.settings.title': {
    defaultMessage: 'System settings',
    description: 'Page title for system settings administration.',
  },
  'administration.settings.transcriptionHelp': {
    defaultMessage: 'Telegram voice notes are auto-transcribed with this model before being sent to apps. Leave empty to disable.',
    description: 'Help text for the default speech-to-text model and Telegram voice-note behavior.',
  },
  'administration.settings.transcriptionLabel': {
    defaultMessage: 'STT',
    description: 'Short label for the default speech-to-text model setting.',
  },
  'administration.settings.transcriptionPlaceholder': {
    defaultMessage: 'Select speech-to-text model',
    description: 'Placeholder for selecting the default speech-to-text model.',
  },
  'administration.settings.visionHelp': {
    defaultMessage: 'Default model for image → text tasks.',
    description: 'Help text for the default vision model.',
  },
  'administration.settings.visionPlaceholder': {
    defaultMessage: 'Select vision model',
    description: 'Placeholder for selecting the default vision model.',
  },
  'administration.usage.allTime': {
    defaultMessage: 'All time',
    description: 'Usage report period option covering all recorded time.',
  },
  'administration.usage.app': {
    defaultMessage: 'App',
    description: 'Usage table heading for an app name.',
  },
  'administration.usage.byApp': {
    defaultMessage: 'By app',
    description: 'Title of the usage breakdown by app.',
  },
  'administration.usage.byModel': {
    defaultMessage: 'By model',
    description: 'Title of the usage breakdown by model.',
  },
  'administration.usage.byUser': {
    defaultMessage: 'By user',
    description: 'Title of the usage breakdown by user.',
  },
  'administration.usage.cached': {
    defaultMessage: 'Cached',
    description: 'Usage table heading for cached input tokens.',
  },
  'administration.usage.cachedCount': {
    defaultMessage: '{formattedCount} cached',
    description: 'Summary text showing the locale-formatted number of cached input tokens. {count} is the numeric count.',
  },
  'administration.usage.calls': {
    defaultMessage: 'Calls',
    description: 'Usage metric label for model calls.',
  },
  'administration.usage.cost': {
    defaultMessage: 'Cost',
    description: 'Usage table heading for estimated cost.',
  },
  'administration.usage.days': {
    defaultMessage: '{formattedCount} day | {formattedCount} days',
    description: 'Usage report period option measured in days. {count} selects the plural form; {formattedCount} is locale-formatted.',
  },
  'administration.usage.deleted': {
    defaultMessage: 'deleted',
    description: 'Lowercase state badge for a deleted app or user in durable usage records.',
  },
  'administration.usage.description': {
    defaultMessage: 'LLM token spend across every app, from the durable ledger - usage from apps that have since been deleted is still counted (and marked).',
    description: 'Explanation of the durable workspace usage report.',
  },
  'administration.usage.empty': {
    defaultMessage: 'No usage in this window.',
    description: 'Empty state for a usage breakdown in the selected period.',
  },
  'administration.usage.model': {
    defaultMessage: 'Model',
    description: 'Usage table heading for the backend model ID.',
  },
  'administration.usage.owner': {
    defaultMessage: 'Owner',
    description: 'Usage table heading for an app owner.',
  },
  'administration.usage.provider': {
    defaultMessage: 'Provider',
    description: 'Usage table heading for a provider slug or catalog ID.',
  },
  'administration.usage.system': {
    defaultMessage: 'system',
    description: 'Lowercase state badge for system-generated usage.',
  },
  'administration.usage.title': {
    defaultMessage: 'Usage',
    description: 'Page title for workspace model usage administration.',
  },
  'administration.usage.tokensIn': {
    defaultMessage: 'Tokens in',
    description: 'Usage metric label for input tokens.',
  },
  'administration.usage.tokensOut': {
    defaultMessage: 'Tokens out',
    description: 'Usage metric label for output tokens.',
  },
  'administration.usage.totalCost': {
    defaultMessage: 'Total cost',
    description: 'Usage summary metric label for total estimated cost.',
  },
  'administration.usage.user': {
    defaultMessage: 'User',
    description: 'Usage table heading for a user email or system identity.',
  },
  'administration.users.action.add': {
    defaultMessage: 'Add User',
    description: 'Button and dialog title for adding a workspace user.',
  },
  'administration.users.action.deleteAria': {
    defaultMessage: 'Delete user',
    description: 'Accessible label for a button that deletes a workspace user.',
  },
  'administration.users.confirmDelete': {
    defaultMessage: 'Delete user "{email}"? This cannot be undone.',
    description: 'Confirmation before deleting a user. Email is the user email and must not be translated.',
  },
  'administration.users.copied': {
    defaultMessage: 'Copied',
    description: 'Success toast shown after copying a temporary password.',
  },
  'administration.users.copyPasswordAria': {
    defaultMessage: 'Copy temporary password',
    description: 'Accessible label for the button that copies a one-time temporary password.',
  },
  'administration.users.createFailed': {
    defaultMessage: 'Create failed',
    description: 'Fallback error shown when creating a workspace user fails.',
  },
  'administration.users.createdAt': {
    defaultMessage: 'Created At',
    description: 'Table heading for the date a workspace user was created.',
  },
  'administration.users.deleteFailed': {
    defaultMessage: 'Delete failed',
    description: 'Fallback error shown when deleting a workspace user fails.',
  },
  'administration.users.deleted': {
    defaultMessage: 'User deleted',
    description: 'Success toast shown after deleting a workspace user.',
  },
  'administration.users.displayName': {
    defaultMessage: 'Display Name',
    description: 'Field label and table heading for a workspace user display name.',
  },
  'administration.users.displayNameExample': {
    defaultMessage: 'Jane Doe',
    description: 'Example placeholder for a new user display name.',
  },
  'administration.users.email': {
    defaultMessage: 'Email',
    description: 'Field label and table heading for a workspace user email address.',
  },
  'administration.users.emailExample': {
    defaultMessage: "user{'@'}example.com",
    description: 'Example placeholder for a new user email address. Keep it as a valid example-domain address.',
  },
  'administration.users.empty': {
    defaultMessage: 'No users found.',
    description: 'Empty state for the workspace users table.',
  },
  'administration.users.actions': {
    defaultMessage: 'Actions',
    description: 'Table heading for workspace user row actions.',
  },
  'administration.users.passwordHandoff': {
    defaultMessage: "Share this one-time password with {email}. They'll be required to set their own password or register a passkey on first sign-in. It won't be shown again.",
    description: 'Instructions for handing a one-time password to a newly created user. Email must not be translated.',
  },
  'administration.users.role': {
    defaultMessage: 'Role',
    description: 'Field label and table heading for a workspace user role.',
  },
  'administration.users.role.admin': {
    defaultMessage: 'Admin',
    description: 'Display label for the workspace administrator role.',
  },
  'administration.users.role.manager': {
    defaultMessage: 'Manager',
    description: 'Display label for the workspace manager role.',
  },
  'administration.users.role.user': {
    defaultMessage: 'User',
    description: 'Display label for the regular workspace user role.',
  },
  'administration.users.roleUpdated': {
    defaultMessage: 'Role updated',
    description: 'Success toast shown after changing a workspace user role.',
  },
  'administration.users.title': {
    defaultMessage: 'Users',
    description: 'Page title for workspace user administration.',
  },
  'administration.users.updateFailed': {
    defaultMessage: 'Update failed',
    description: 'Fallback error shown when changing a workspace user role fails.',
  },
  'administration.users.userCreated': {
    defaultMessage: 'User created',
    description: 'Title of the one-time password dialog after creating a workspace user.',
  },
})
