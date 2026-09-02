import { defineMessages } from './define'

export const authMessages = defineMessages({
  'auth.product.airlock': {
    defaultMessage: 'Airlock',
    description: 'Airlock product name shown in authentication and application-shell UI.',
  },
  'auth.product.assistant': {
    defaultMessage: 'Airlock Assistant',
    description: 'Name of the built-in Airlock assistant in the chat navigation.',
  },
  'auth.product.cli': {
    defaultMessage: 'Airlock CLI',
    description: 'Name of the Airlock command-line client on the device authorization page.',
  },
  'auth.product.web': {
    defaultMessage: 'Airlock Web',
    description: 'Name of the Airlock web client in the account session list.',
  },
  'auth.product.airCli': {
    defaultMessage: 'air CLI',
    description: 'Name of the air command-line client when no client name is supplied.',
  },
  'auth.action.approve': {
    defaultMessage: 'Approve',
    description: 'Button that approves an OAuth or device sign-in request.',
  },
  'auth.action.back': {
    defaultMessage: 'Back',
    description: 'Button or accessible label that returns to the previous setup section.',
  },
  'auth.action.cancel': {
    defaultMessage: 'Cancel',
    description: 'Button that cancels an authentication or security action.',
  },
  'auth.action.continue': {
    defaultMessage: 'Continue',
    description: 'Button that continues passkey registration.',
  },
  'auth.action.delete': {
    defaultMessage: 'Delete',
    description: 'Destructive confirmation button for a conversation or passkey.',
  },
  'auth.action.deny': {
    defaultMessage: 'Deny',
    description: 'Button that denies an OAuth or device sign-in request.',
  },
  'auth.action.finish': {
    defaultMessage: 'Finish',
    description: 'Button that completes Airlock onboarding.',
  },
  'auth.action.next': {
    defaultMessage: 'Next',
    description: 'Button that advances to the next onboarding step.',
  },
  'auth.action.remove': {
    defaultMessage: 'Remove',
    description: 'Destructive confirmation button for removing a password.',
  },
  'auth.action.retry': {
    defaultMessage: 'Retry',
    description: 'Button that retries loading provider options during onboarding.',
  },
  'auth.action.save': {
    defaultMessage: 'Save',
    description: 'Button that saves a profile or passkey name.',
  },
  'auth.shell.linkOutOfDate': {
    defaultMessage: 'Link out of date',
    description: 'Warning title shown when an app URL contains a stale app slug.',
  },
  'auth.shell.staleAppLink': {
    defaultMessage: 'No app “{slug}” - it may have been renamed. Pick it from the list.',
    description: 'Warning detail for a stale app link. {slug} is the unchanged app slug from the URL.',
  },
  'auth.shell.security': {
    defaultMessage: 'Security',
    description: 'Security section label in settings navigation and page heading.',
  },
  'auth.shell.resources': {
    defaultMessage: 'Resources',
    description: 'Resources section label in settings navigation.',
  },
  'auth.shell.bridges': {
    defaultMessage: 'Bridges',
    description: 'Bridges section label in settings navigation.',
  },
  'auth.shell.providers': {
    defaultMessage: 'Providers',
    description: 'Providers section label in settings navigation and onboarding guidance.',
  },
  'auth.shell.models': {
    defaultMessage: 'Models',
    description: 'Models section label in settings navigation.',
  },
  'auth.shell.systemDefaults': {
    defaultMessage: 'System defaults',
    description: 'System defaults section label in settings navigation.',
  },
  'auth.shell.usage': {
    defaultMessage: 'Usage',
    description: 'Usage section label in settings navigation.',
  },
  'auth.shell.users': {
    defaultMessage: 'Users',
    description: 'Users section label in settings navigation.',
  },
  'auth.shell.manageApps': {
    defaultMessage: 'Manage apps',
    description: 'App administration section label in settings navigation.',
  },
  'auth.shell.logoutFailed': {
    defaultMessage: 'Logout failed',
    description: 'Fallback error shown when signing out fails without a server error.',
  },
  'auth.shell.settings': {
    defaultMessage: 'Settings',
    description: 'Settings menu item and shell heading.',
  },
  'auth.shell.lightMode': {
    defaultMessage: 'Light mode',
    description: 'Menu action that switches the application to light mode.',
  },
  'auth.shell.darkMode': {
    defaultMessage: 'Dark mode',
    description: 'Menu action that switches the application to dark mode.',
  },
  'auth.shell.logout': {
    defaultMessage: 'Logout',
    description: 'Menu action that signs the current user out.',
  },
  'auth.shell.account': {
    defaultMessage: 'Account',
    description: 'Fallback user-menu label when the account has no display name or email.',
  },
  'auth.shell.noApps': {
    defaultMessage: 'No apps yet',
    description: 'Disabled new-chat menu item shown when no apps exist.',
  },
  'auth.shell.allApps': {
    defaultMessage: 'All apps',
    description: 'New-chat menu item that opens the full apps list.',
  },
  'auth.shell.appFallback': {
    defaultMessage: 'App',
    description: 'Fallback app name in the conversation sidebar.',
  },
  'auth.shell.untitledConversation': {
    defaultMessage: 'Untitled conversation',
    description: 'Fallback title for a conversation that has no title.',
  },
  'auth.shell.deleteConversationMessage': {
    defaultMessage: 'Delete "{title}"? This removes its history permanently.',
    description: 'Confirmation text before permanently deleting a conversation. {title} is unchanged user or generated content.',
  },
  'auth.shell.deleteConversation': {
    defaultMessage: 'Delete conversation',
    description: 'Conversation deletion dialog heading and delete-button accessible label.',
  },
  'auth.shell.chatTitle': {
    defaultMessage: '{name}: {title}',
    description: 'Shell heading combining an unchanged app or assistant name with an unchanged conversation title.',
  },
  'auth.shell.newChat': {
    defaultMessage: 'New chat',
    description: 'Sidebar button that starts a new conversation.',
  },
  'auth.shell.noConversations': {
    defaultMessage: 'No conversations yet',
    description: 'Empty-state text in the conversation sidebar.',
  },
  'auth.shell.cyborgApps': {
    defaultMessage: 'Cyborg Apps',
    description: 'Primary sidebar navigation label for the apps page.',
  },
  'auth.relay.missingParameters': {
    defaultMessage: 'Missing relay parameters.',
    description: 'Error shown when an authentication relay URL lacks required parameters.',
  },
  'auth.relay.failed': {
    defaultMessage: 'Failed to authenticate.',
    description: 'Fallback error shown when authentication relay exchange fails.',
  },
  'auth.relay.authenticating': {
    defaultMessage: 'Authenticating...',
    description: 'Progress text while an authentication relay is being exchanged.',
  },
  'auth.login.welcomeBack': {
    defaultMessage: 'Welcome back',
    description: 'Success toast after the user signs in.',
  },
  'auth.login.passkeyFailed': {
    defaultMessage: 'Passkey sign-in failed.',
    description: 'Fallback error when passkey sign-in fails without a server error.',
  },
  'auth.login.credentialsRequired': {
    defaultMessage: 'Email and password are required.',
    description: 'Validation error when password sign-in fields are empty.',
  },
  'auth.login.failed': {
    defaultMessage: 'Login failed.',
    description: 'Fallback error when password sign-in fails without a server error.',
  },
  'auth.login.withPasskey': {
    defaultMessage: 'Sign in with a passkey',
    description: 'Primary login button for passkey authentication.',
  },
  'auth.login.hidePassword': {
    defaultMessage: 'Hide password sign-in',
    description: 'Toggle that hides the password sign-in form.',
  },
  'auth.login.usePassword': {
    defaultMessage: 'Use a password instead',
    description: 'Toggle that reveals the password sign-in form.',
  },
  'auth.login.email': {
    defaultMessage: 'Email',
    description: 'Email-address field label in login and onboarding forms.',
  },
  'auth.login.password': {
    defaultMessage: 'Password',
    description: 'Password field label in login and onboarding forms.',
  },
  'auth.login.signIn': {
    defaultMessage: 'Sign In',
    description: 'Button that submits the password sign-in form.',
  },
  'auth.login.optionalEmail': {
    defaultMessage: 'Email (optional)',
    description: 'Optional email field label used to scope passkey sign-in.',
  },
  'auth.login.firstTimeSetup': {
    defaultMessage: 'First time? Set up Airlock',
    description: 'Link from login to first-time Airlock setup.',
  },
  'auth.changePassword.passkeyAdded': {
    defaultMessage: 'Passkey added - account secured',
    description: 'Success toast after adding the passkey required to secure an account.',
  },
  'auth.passkey.defaultName': {
    defaultMessage: 'Passkey',
    description: 'Default friendly name assigned to a passkey when the user does not provide one.',
  },
  'auth.changePassword.passkeyRegistrationFailed': {
    defaultMessage: 'Failed to register passkey.',
    description: 'Fallback error when required passkey registration fails.',
  },
  'auth.validation.allFieldsRequired': {
    defaultMessage: 'All fields are required.',
    description: 'Validation error when a password-change field is empty.',
  },
  'auth.changePassword.newPasswordsMismatch': {
    defaultMessage: 'New passwords do not match.',
    description: 'Validation error when new-password and confirmation fields differ.',
  },
  'auth.changePassword.weak': {
    defaultMessage: 'New password is too weak - choose a longer or less predictable one.',
    description: 'Validation error when a new password does not meet the strength requirement.',
  },
  'auth.changePassword.changed': {
    defaultMessage: 'Password changed',
    description: 'Success toast after changing the account password.',
  },
  'auth.changePassword.failed': {
    defaultMessage: 'Failed to change password.',
    description: 'Fallback error when changing the account password fails.',
  },
  'auth.changePassword.secureAccount': {
    defaultMessage: 'Secure your account',
    description: 'Heading for the required credential-change page.',
  },
  'auth.changePassword.instructions': {
    defaultMessage: 'Register a passkey (recommended) or set a new password before continuing.',
    description: 'Instructions on the required credential-change page.',
  },
  'auth.changePassword.registerPasskey': {
    defaultMessage: 'Register a passkey',
    description: 'Button that registers a passkey to secure the account.',
  },
  'auth.changePassword.orSetPassword': {
    defaultMessage: 'or set a password',
    description: 'Divider text between passkey and password credential options.',
  },
  'auth.changePassword.currentPassword': {
    defaultMessage: 'Current Password',
    description: 'Current-password field label on the required password-change page.',
  },
  'auth.changePassword.newPassword': {
    defaultMessage: 'New Password',
    description: 'New-password field label on the required password-change page.',
  },
  'auth.changePassword.confirmNewPassword': {
    defaultMessage: 'Confirm New Password',
    description: 'New-password confirmation field label on the required password-change page.',
  },
  'auth.changePassword.action': {
    defaultMessage: 'Change Password',
    description: 'Button that submits the required password change.',
  },
  'auth.consent.missingParameters': {
    defaultMessage: 'Missing OAuth parameters. Cannot continue.',
    description: 'Error shown when an OAuth consent URL lacks required parameters.',
  },
  'auth.consent.missingRedirect': {
    defaultMessage: 'Server did not return a redirect URL.',
    description: 'Error shown when approved OAuth consent has no redirect destination.',
  },
  'auth.consent.failed': {
    defaultMessage: 'Consent failed',
    description: 'Fallback error when recording an OAuth consent decision fails.',
  },
  'auth.consent.title': {
    defaultMessage: 'Authorize external app',
    description: 'Heading for the OAuth consent page.',
  },
  'auth.consent.request': {
    defaultMessage: '{client} is requesting access to your app {app}.',
    description: 'OAuth consent summary. {client} and {app} are unchanged external client and app identifiers or names.',
  },
  'auth.consent.appWithSlug': {
    defaultMessage: '{name} ({slug})',
    description: 'OAuth target app formatted with its unchanged display name and slug.',
  },
  'auth.consent.abilities': {
    defaultMessage: 'It will be able to:',
    description: 'Introduction to the permissions requested by an OAuth client.',
  },
  'auth.consent.sendAndCall': {
    defaultMessage: 'Send prompts and call the tools this app exposes (scope {scope}).',
    description: 'OAuth permission description. {scope} is an unchanged OAuth scope identifier.',
  },
  'auth.consent.readConversations': {
    defaultMessage: 'Read your conversations with this app.',
    description: 'OAuth permission explaining access to app conversations.',
  },
  'auth.consent.duration': {
    defaultMessage: 'Access is granted for 90 days. You can revoke it any time in',
    description: 'OAuth grant duration notice immediately before the settings link.',
  },
  'auth.consent.connectedAppsLink': {
    defaultMessage: 'Settings → Connected apps',
    description: 'Link label pointing to settings where OAuth grants can be revoked.',
  },
  'auth.device.lookupFailed': {
    defaultMessage: 'Code lookup failed',
    description: 'Fallback error when looking up a device sign-in code fails.',
  },
  'auth.device.updateFailed': {
    defaultMessage: 'Device login update failed',
    description: 'Fallback error when approving or denying a device sign-in fails.',
  },
  'auth.device.title': {
    defaultMessage: 'Sign in to Airlock CLI',
    description: 'Heading for authorizing an Airlock CLI device sign-in.',
  },
  'auth.device.instructions': {
    defaultMessage: 'Enter the code shown in your terminal. For security, Airlock does not accept login codes from links.',
    description: 'Security instructions on the device sign-in page.',
  },
  'auth.device.code': {
    defaultMessage: 'Device code',
    description: 'Label for the device sign-in code input.',
  },
  'auth.device.codePlaceholder': {
    defaultMessage: 'ABCD-EFGH',
    description: 'Non-secret example format shown in the device code input.',
  },
  'auth.device.checkCode': {
    defaultMessage: 'Check code',
    description: 'Button that looks up a device sign-in code.',
  },
  'auth.device.codeSummary': {
    defaultMessage: 'Code',
    description: 'Label for the normalized code in a device sign-in request summary.',
  },
  'auth.device.requestedBy': {
    defaultMessage: 'Requested by',
    description: 'Label for the client requesting device sign-in.',
  },
  'auth.device.device': {
    defaultMessage: 'Device',
    description: 'Label for the device name in a sign-in request summary.',
  },
  'auth.device.account': {
    defaultMessage: 'Account',
    description: 'Label for the Airlock account in a device sign-in request summary.',
  },
  'auth.device.status': {
    defaultMessage: 'Status',
    description: 'Label for the status of a device sign-in request.',
  },
  'auth.device.status.pending': {
    defaultMessage: 'Pending',
    description: 'Device sign-in request status while it awaits approval or denial.',
  },
  'auth.device.status.approved': {
    defaultMessage: 'Approved',
    description: 'Device sign-in request status after it is approved.',
  },
  'auth.device.status.denied': {
    defaultMessage: 'Denied',
    description: 'Device sign-in request status after it is denied.',
  },
  'auth.device.status.expired': {
    defaultMessage: 'Expired',
    description: 'Device sign-in request status after its code expires.',
  },
  'auth.identity.external': {
    defaultMessage: 'External',
    description: 'Fallback platform label when a linked identity has no platform identifier.',
  },
  'auth.identity.invalidLink': {
    defaultMessage: 'Invalid link - missing parameters.',
    description: 'Error shown when an identity-link URL lacks required parameters.',
  },
  'auth.identity.verifyFailed': {
    defaultMessage: 'Failed to verify link.',
    description: 'Fallback error when verifying an identity-link request fails.',
  },
  'auth.identity.linkedToast': {
    defaultMessage: '{platform} account linked',
    description: 'Success toast after linking an external account. {platform} is an unchanged platform label.',
  },
  'auth.identity.linkFailed': {
    defaultMessage: 'Failed to link account.',
    description: 'Fallback error when linking an external account fails.',
  },
  'auth.identity.verifying': {
    defaultMessage: 'Verifying link…',
    description: 'Progress text while an external identity-link request is verified.',
  },
  'auth.identity.confirmTitle': {
    defaultMessage: 'Link {platform} account?',
    description: 'Identity-link confirmation heading. {platform} is an unchanged platform label.',
  },
  'auth.identity.confirmInstructions': {
    defaultMessage: 'Confirm the details below before linking. You should only proceed if you personally initiated this from the bot.',
    description: 'Security warning before linking an external identity.',
  },
  'auth.identity.platform': {
    defaultMessage: 'Platform',
    description: 'Label for the external platform in an identity-link preview.',
  },
  'auth.identity.bot': {
    defaultMessage: 'Bot',
    description: 'Label for the bridge bot in an identity-link preview.',
  },
  'auth.identity.unknown': {
    defaultMessage: '(unknown)',
    description: 'Fallback bridge-bot name in an identity-link preview.',
  },
  'auth.identity.platformUser': {
    defaultMessage: '{platform} user',
    description: 'Label for an external-platform user. {platform} is an unchanged platform label.',
  },
  'auth.identity.userId': {
    defaultMessage: 'ID: {id}',
    description: 'External-platform user identifier. {id} is unchanged.',
  },
  'auth.identity.linkingTo': {
    defaultMessage: 'Linking to',
    description: 'Label for the Airlock account receiving an external identity link.',
  },
  'auth.identity.confirmAndLink': {
    defaultMessage: 'Confirm & link',
    description: 'Button that confirms an external identity link.',
  },
  'auth.identity.linking': {
    defaultMessage: 'Linking your account…',
    description: 'Progress text while an external identity is being linked.',
  },
  'auth.identity.success': {
    defaultMessage: 'Account linked successfully! You can close this page and return to {platform}.',
    description: 'Identity-link success message. {platform} is an unchanged platform label.',
  },
  'auth.identity.goToApps': {
    defaultMessage: 'Go to Apps',
    description: 'Button that leaves identity linking or an error page for the apps list.',
  },
  'auth.notFound.message': {
    defaultMessage: 'The page you\'re looking for doesn\'t exist.',
    description: 'Message on the not-found page.',
  },
  'auth.notFound.code': {
    defaultMessage: '404',
    description: 'HTTP status code shown as the heading on the not-found page.',
  },
  'auth.passwordStrength.veryWeak': {
    defaultMessage: 'Very weak',
    description: 'Lowest password-strength rating.',
  },
  'auth.passwordStrength.weak': {
    defaultMessage: 'Weak',
    description: 'Low password-strength rating.',
  },
  'auth.passwordStrength.fair': {
    defaultMessage: 'Fair',
    description: 'Medium password-strength rating.',
  },
  'auth.passwordStrength.strong': {
    defaultMessage: 'Strong',
    description: 'High password-strength rating.',
  },
  'auth.passwordStrength.veryStrong': {
    defaultMessage: 'Very strong',
    description: 'Highest password-strength rating.',
  },
  'auth.passwordStrength.withWarning': {
    defaultMessage: '{label} - {warning}',
    description: 'Password-strength rating followed by unchanged feedback from the password-scoring library.',
  },
  'auth.activation.setupDataFailed': {
    defaultMessage: 'Setup data could not be loaded. Retry by returning to Providers and selecting Next.',
    description: 'Onboarding error explaining how to retry loading model setup data.',
  },
  'auth.activation.codeRequired': {
    defaultMessage: 'Activation code is required.',
    description: 'Validation error when a required activation code is empty.',
  },
  'auth.activation.emailRequired': {
    defaultMessage: 'Email is required.',
    description: 'Validation error when onboarding email is empty.',
  },
  'auth.activation.enterPassword': {
    defaultMessage: 'Enter and confirm a password.',
    description: 'Validation error when onboarding password fields are empty.',
  },
  'auth.activation.passwordsMismatch': {
    defaultMessage: 'Passwords do not match.',
    description: 'Validation error when password and confirmation fields differ.',
  },
  'auth.activation.passwordWeak': {
    defaultMessage: 'Password is too weak - choose a longer or less predictable one.',
    description: 'Validation error when a password does not meet the strength requirement.',
  },
  'auth.activation.passkeyCancelled': {
    defaultMessage: 'Passkey setup was cancelled. Try again, or uncheck "Use a passkey" to set a password instead.',
    description: 'Onboarding guidance after the user cancels required passkey setup.',
  },
  'auth.activation.failed': {
    defaultMessage: 'Activation failed.',
    description: 'Fallback error when first-time Airlock activation fails.',
  },
  'auth.activation.capability.text': {
    defaultMessage: 'Text',
    description: 'Text-generation capability label during provider onboarding.',
  },
  'auth.activation.capability.vision': {
    defaultMessage: 'Vision',
    description: 'Image-understanding capability label during provider onboarding.',
  },
  'auth.activation.capability.transcription': {
    defaultMessage: 'Transcription',
    description: 'Speech-transcription capability label during provider onboarding.',
  },
  'auth.activation.capability.speech': {
    defaultMessage: 'Speech',
    description: 'Speech-generation capability label during provider onboarding.',
  },
  'auth.activation.capability.imageGen': {
    defaultMessage: 'Image gen',
    description: 'Image-generation capability label during provider onboarding.',
  },
  'auth.activation.capability.embedding': {
    defaultMessage: 'Embedding',
    description: 'Embedding capability label during provider onboarding.',
  },
  'auth.activation.capability.webSearch': {
    defaultMessage: 'Web search',
    description: 'Web-search capability label during provider onboarding.',
  },
  'auth.activation.providerCatalogFailed': {
    defaultMessage: 'Provider catalog could not be loaded.',
    description: 'Error when the provider catalog cannot be loaded during onboarding.',
  },
  'auth.activation.providerOptionsFailed': {
    defaultMessage: 'Provider options could not be loaded.',
    description: 'Fallback error when provider onboarding options cannot be loaded.',
  },
  'auth.activation.providerFormInvalid': {
    defaultMessage: 'Enter a display name, valid unique-style slug, valid URL, and any required API key.',
    description: 'Validation error summarizing invalid provider onboarding fields.',
  },
  'auth.activation.providerAdded': {
    defaultMessage: 'Added {provider}',
    description: 'Success toast after adding a provider. {provider} is an unchanged provider name or identifier.',
  },
  'auth.activation.providerCatalogRefreshFailed': {
    defaultMessage: 'Provider catalog could not be refreshed.',
    description: 'Error when the provider catalog cannot be refreshed after adding a provider.',
  },
  'auth.activation.createProviderFailed': {
    defaultMessage: 'Failed to create provider.',
    description: 'Fallback error when adding a provider during onboarding fails.',
  },
  'auth.activation.modelsDefaultsFailed': {
    defaultMessage: 'Models and defaults could not be loaded. Try again.',
    description: 'Fallback error when onboarding cannot load model choices and defaults.',
  },
  'auth.activation.setupSkipped': {
    defaultMessage: 'Setup skipped',
    description: 'Toast title after skipping optional onboarding.',
  },
  'auth.activation.setupSkippedDetail': {
    defaultMessage: 'You can configure providers and local endpoints under Providers, defaults under Settings, and Telegram under Bridges.',
    description: 'Toast explaining where skipped onboarding options can be configured later.',
  },
  'auth.activation.default.buildModel': {
    defaultMessage: 'Build Model',
    description: 'Default build-model field label during onboarding.',
  },
  'auth.activation.default.buildModelHelp': {
    defaultMessage: 'Used by Sol to generate app code.',
    description: 'Help text for the default build model; Sol is a product name.',
  },
  'auth.activation.default.executionText': {
    defaultMessage: 'Execution (Text)',
    description: 'Default text-execution model field label during onboarding.',
  },
  'auth.activation.default.executionTextHelp': {
    defaultMessage: 'Runtime default for LLM calls.',
    description: 'Help text for the default text-execution model.',
  },
  'auth.activation.default.vision': {
    defaultMessage: 'Vision',
    description: 'Default vision-model field label during onboarding.',
  },
  'auth.activation.default.visionHelp': {
    defaultMessage: 'Image → text.',
    description: 'Help text describing the default vision model conversion.',
  },
  'auth.activation.default.stt': {
    defaultMessage: 'STT',
    description: 'Default speech-to-text model field label during onboarding.',
  },
  'auth.activation.default.sttHelp': {
    defaultMessage: 'Speech-to-text.',
    description: 'Help text for the default speech-to-text model.',
  },
  'auth.activation.default.tts': {
    defaultMessage: 'TTS',
    description: 'Default text-to-speech model field label during onboarding.',
  },
  'auth.activation.default.ttsHelp': {
    defaultMessage: 'Text-to-speech.',
    description: 'Help text for the default text-to-speech model.',
  },
  'auth.activation.default.imageGen': {
    defaultMessage: 'Image Gen',
    description: 'Default image-generation model field label during onboarding.',
  },
  'auth.activation.default.imageGenHelp': {
    defaultMessage: 'Text-to-image generation.',
    description: 'Help text for the default image-generation model.',
  },
  'auth.activation.default.embedding': {
    defaultMessage: 'Embedding',
    description: 'Default embedding-model field label during onboarding.',
  },
  'auth.activation.default.embeddingHelp': {
    defaultMessage: 'Text → vector embeddings.',
    description: 'Help text for the default embedding model conversion.',
  },
  'auth.activation.default.webSearch': {
    defaultMessage: 'Web Search',
    description: 'Default web-search model field label during onboarding.',
  },
  'auth.activation.default.webSearchHelp': {
    defaultMessage: 'Web search backend + model.',
    description: 'Help text for the default web-search backend and model.',
  },
  'auth.activation.saveDefaultsFailed': {
    defaultMessage: 'Failed to save defaults.',
    description: 'Fallback error when saving onboarding model defaults fails.',
  },
  'auth.activation.telegramTokenRequired': {
    defaultMessage: 'Paste the Telegram bot token first.',
    description: 'Validation error when the Telegram manager bot token is empty.',
  },
  'auth.activation.telegramBotAdded': {
    defaultMessage: 'Telegram manager bot added',
    description: 'Success toast after adding the Telegram manager bot.',
  },
  'auth.activation.telegramBotFailed': {
    defaultMessage: 'Failed to add Telegram manager bot.',
    description: 'Fallback error when adding the Telegram manager bot fails.',
  },
  'auth.activation.activated': {
    defaultMessage: 'Airlock activated',
    description: 'Success toast after completing Airlock activation.',
  },
  'auth.activation.alreadyActivated': {
    defaultMessage: 'Already Activated',
    description: 'Heading shown when Airlock setup has already been completed.',
  },
  'auth.activation.alreadyActivatedDetail': {
    defaultMessage: 'Airlock has already been set up. Please sign in.',
    description: 'Explanation shown when Airlock setup has already been completed.',
  },
  'auth.activation.goToLogin': {
    defaultMessage: 'Go to Login',
    description: 'Button from completed setup to the login page.',
  },
  'auth.activation.setupTitle': {
    defaultMessage: 'Airlock Setup',
    description: 'Heading for the Airlock onboarding wizard.',
  },
  'auth.activation.step.account': {
    defaultMessage: 'Account',
    description: 'Account step label in the onboarding wizard.',
  },
  'auth.activation.step.providers': {
    defaultMessage: 'Providers',
    description: 'Providers step label in the onboarding wizard.',
  },
  'auth.activation.step.defaults': {
    defaultMessage: 'Defaults',
    description: 'Model defaults step label in the onboarding wizard.',
  },
  'auth.activation.step.telegram': {
    defaultMessage: 'Telegram',
    description: 'Telegram step label in the onboarding wizard; Telegram is a product name.',
  },
  'auth.activation.activationCode': {
    defaultMessage: 'Activation Code',
    description: 'Activation-code field label during first-time setup.',
  },
  'auth.activation.displayName': {
    defaultMessage: 'Display Name',
    description: 'Administrator display-name field label during onboarding.',
  },
  'auth.activation.language': {
    defaultMessage: 'Language',
    description: 'User-interface language selector label during onboarding.',
  },
  'auth.locale.english': {
    defaultMessage: 'English',
    description: 'Localized name of the English user-interface locale.',
  },
  'auth.locale.russian': {
    defaultMessage: 'Russian',
    description: 'Localized name of the Russian user-interface locale.',
  },
  'auth.activation.usePasskey': {
    defaultMessage: 'Use a passkey (uncheck to set a password instead)',
    description: 'Onboarding checkbox label selecting passkey rather than password authentication.',
  },
  'auth.activation.confirmPassword': {
    defaultMessage: 'Confirm Password',
    description: 'Password-confirmation field label during onboarding.',
  },
  'auth.activation.createAccountPasskey': {
    defaultMessage: 'Create account & passkey',
    description: 'Button that creates the administrator account and its first passkey.',
  },
  'auth.activation.createAccount': {
    defaultMessage: 'Create account',
    description: 'Button that creates the administrator account with a password.',
  },
  'auth.activation.providerLoadContext': {
    defaultMessage: 'Account setup is complete, but provider options could not be loaded: {error}',
    description: 'Onboarding provider-load error. {error} is unchanged server or fallback error text.',
  },
  'auth.activation.localProviderNotice': {
    defaultMessage: 'Local and OpenAI-compatible endpoints require model confirmation. Configure them after activation under Providers.',
    description: 'Onboarding notice about configuring local and OpenAI-compatible providers.',
  },
  'auth.activation.capabilities': {
    defaultMessage: 'Capabilities',
    description: 'Heading for provider capability coverage during onboarding.',
  },
  'auth.activation.notConfigured': {
    defaultMessage: 'Not yet configured',
    description: 'Provider capability status when no configured provider supports it.',
  },
  'auth.activation.provider': {
    defaultMessage: 'Provider',
    description: 'Provider selector label during onboarding.',
  },
  'auth.activation.provides': {
    defaultMessage: 'Provides:',
    description: 'Introduction to capability tags for the selected provider.',
  },
  'auth.activation.slug': {
    defaultMessage: 'Slug',
    description: 'Provider slug field label during onboarding.',
  },
  'auth.activation.slugHelp': {
    defaultMessage: 'Unique within this provider type. Suggestions skip slugs already in use; manual edits are preserved.',
    description: 'Help text explaining provider slug uniqueness and suggestions.',
  },
  'auth.activation.slugInvalid': {
    defaultMessage: 'Use 1-63 lowercase letters, numbers, and single hyphens.',
    description: 'Provider slug format validation guidance.',
  },
  'auth.activation.baseUrl': {
    defaultMessage: 'Base URL (optional)',
    description: 'Optional provider base-URL field label during onboarding.',
  },
  'auth.activation.urlInvalid': {
    defaultMessage: 'Enter an absolute HTTP(S) URL without credentials, query, or fragment.',
    description: 'Provider base-URL format validation guidance.',
  },
  'auth.activation.apiKey': {
    defaultMessage: 'API Key',
    description: 'Provider API-key field label during onboarding.',
  },
  'auth.activation.apiKeyRequired': {
    defaultMessage: 'Hosted providers require an API key.',
    description: 'Validation guidance when a hosted provider API key is empty.',
  },
  'auth.activation.addProvider': {
    defaultMessage: 'Add provider',
    description: 'Button that adds a provider during onboarding.',
  },
  'auth.activation.skipSetup': {
    defaultMessage: 'Skip setup',
    description: 'Button that skips optional provider onboarding.',
  },
  'auth.activation.defaultsInstructions': {
    defaultMessage: 'Pick a default model for each capability. Apps inherit these unless they override. You can change them anytime under Settings.',
    description: 'Instructions for choosing model defaults during onboarding.',
  },
  'auth.activation.noModels': {
    defaultMessage: 'No models yet. Go back and add a provider that offers at least one capability.',
    description: 'Empty state when no configured provider offers selectable models.',
  },
  'auth.activation.telegramTitle': {
    defaultMessage: 'Add a Telegram manager bot',
    description: 'Heading for Telegram manager-bot onboarding.',
  },
  'auth.activation.telegramIntro': {
    defaultMessage: 'The manager bot lets Airlock create new Telegram bots for apps through Telegram\'s managed-bots flow. It must be a Telegram bot with bot-management permission enabled.',
    description: 'Explanation of the Telegram manager bot; Airlock and Telegram are product names.',
  },
  'auth.activation.managerConfigured': {
    defaultMessage: 'Manager bot configured: {name}',
    description: 'Success message for a configured Telegram manager bot. {name} is unchanged bot data.',
  },
  'auth.activation.managerConfiguredError': {
    defaultMessage: 'Manager bot configured: {name} - {error}',
    description: 'Configured Telegram manager-bot status with unchanged bot name and backend error.',
  },
  'auth.activation.telegramChecklist': {
    defaultMessage: 'Telegram setup checklist',
    description: 'Heading for Telegram manager-bot setup steps.',
  },
  'auth.activation.telegramChecklistCreate': {
    defaultMessage: 'Open @BotFather in Telegram and create a new bot, or choose an existing bot that should manage bot creation.',
    description: 'First Telegram setup step; @BotFather and Telegram are unchanged product identifiers.',
  },
  'auth.activation.telegramChecklistPermission': {
    defaultMessage: 'Open that bot\'s settings in BotFather and enable the management permission for creating/managing bots. Telegram exposes this as can_manage_bots.',
    description: 'Second Telegram setup step; BotFather, Telegram, and can_manage_bots are unchanged identifiers.',
  },
  'auth.activation.telegramChecklistToken': {
    defaultMessage: 'Copy the bot token from BotFather and paste it below.',
    description: 'Third Telegram setup step; BotFather is an unchanged product name.',
  },
  'auth.activation.telegramChecklistVerify': {
    defaultMessage: 'Airlock verifies the token and refuses setup if Telegram has not granted can_manage_bots.',
    description: 'Fourth Telegram setup step; Airlock, Telegram, and can_manage_bots remain unchanged.',
  },
  'auth.activation.telegramBotToken': {
    defaultMessage: 'Telegram bot token',
    description: 'Telegram manager-bot token field label.',
  },
  'auth.activation.telegramBridgeHelp': {
    defaultMessage: 'The bot is saved as an unbound manager bridge. App bots can be created later from Bridges without pasting tokens manually.',
    description: 'Help text explaining how the Telegram manager bot is stored and used.',
  },
  'auth.activation.addManagerBot': {
    defaultMessage: 'Add manager bot',
    description: 'Button that adds the Telegram manager bot.',
  },
  'auth.activation.skipForNow': {
    defaultMessage: 'Skip for now',
    description: 'Button that postpones Telegram manager-bot setup.',
  },
  'auth.activation.alreadySignIn': {
    defaultMessage: 'Already activated? Sign in',
    description: 'Link from onboarding to login for an already activated installation.',
  },
  'auth.security.profile': {
    defaultMessage: 'Profile',
    description: 'Profile card heading on the security page.',
  },
  'auth.security.profileDescription': {
    defaultMessage: 'This name identifies you throughout Airlock.',
    description: 'Explanation of the account display name.',
  },
  'auth.security.displayName': {
    defaultMessage: 'Display name',
    description: 'Account display-name field label on the security page.',
  },
  'auth.security.displayNameUpdated': {
    defaultMessage: 'Display name updated',
    description: 'Success toast after updating the account display name.',
  },
  'auth.security.displayNameFailed': {
    defaultMessage: 'Failed to update display name.',
    description: 'Fallback error when updating the account display name fails.',
  },
  'auth.security.passkeysLoadFailed': {
    defaultMessage: 'Failed to load passkeys.',
    description: 'Fallback error when account passkeys cannot be loaded.',
  },
  'auth.security.passkeyAdded': {
    defaultMessage: 'Passkey added',
    description: 'Success toast after adding a passkey.',
  },
  'auth.security.passkeyAddFailed': {
    defaultMessage: 'Failed to add passkey.',
    description: 'Fallback error when adding a passkey fails.',
  },
  'auth.security.passkeyRenamed': {
    defaultMessage: 'Passkey renamed',
    description: 'Success toast after renaming a passkey.',
  },
  'auth.security.renameFailed': {
    defaultMessage: 'Rename failed',
    description: 'Fallback error when renaming a passkey fails.',
  },
  'auth.security.deletePasskeyMessage': {
    defaultMessage: 'Delete passkey "{name}"? You won\'t be able to sign in with it anymore.',
    description: 'Passkey deletion confirmation. {name} is an unchanged user-provided passkey name.',
  },
  'auth.security.deletePasskey': {
    defaultMessage: 'Delete passkey',
    description: 'Heading for the passkey deletion confirmation dialog.',
  },
  'auth.security.passkeyDeleted': {
    defaultMessage: 'Passkey deleted',
    description: 'Success toast after deleting a passkey.',
  },
  'auth.security.deleteFailed': {
    defaultMessage: 'Delete failed',
    description: 'Fallback error when deleting a passkey fails.',
  },
  'auth.security.passwordsMismatch': {
    defaultMessage: 'Passwords do not match.',
    description: 'Validation error when security-page password fields differ.',
  },
  'auth.security.passwordWeak': {
    defaultMessage: 'Password is too weak - choose a longer or less predictable one.',
    description: 'Validation error when a security-page password is too weak.',
  },
  'auth.security.passwordSaved': {
    defaultMessage: 'Password saved',
    description: 'Success toast after setting or changing a password.',
  },
  'auth.security.passwordSaveFailed': {
    defaultMessage: 'Failed to save password.',
    description: 'Fallback error when setting or changing a password fails.',
  },
  'auth.security.removePasswordMessage': {
    defaultMessage: 'Remove your password? You will only be able to sign in with a passkey.',
    description: 'Warning in the password removal confirmation dialog.',
  },
  'auth.security.removePassword': {
    defaultMessage: 'Remove password',
    description: 'Password removal dialog heading and button label.',
  },
  'auth.security.passwordRemoved': {
    defaultMessage: 'Password removed',
    description: 'Success toast after removing the account password.',
  },
  'auth.security.passwordRemoveFailed': {
    defaultMessage: 'Failed to remove password',
    description: 'Fallback error when removing the account password fails.',
  },
  'auth.security.accessRevoked': {
    defaultMessage: 'Access revoked',
    description: 'Success toast after revoking an authorized app grant.',
  },
  'auth.security.revokeFailed': {
    defaultMessage: 'revoke failed',
    description: 'Fallback error when revoking an app grant or session fails.',
  },
  'auth.security.sessionRevoked': {
    defaultMessage: 'Session revoked',
    description: 'Success toast after revoking an account session.',
  },
  'auth.security.identityUnlinked': {
    defaultMessage: 'Identity unlinked',
    description: 'Success toast after unlinking an external identity.',
  },
  'auth.security.unlinkFailed': {
    defaultMessage: 'unlink failed',
    description: 'Fallback error when unlinking an external identity fails.',
  },
  'auth.security.recentAuthNotice': {
    defaultMessage: 'Credential changes require a sign-in within the last 10 minutes. Sign out and sign in again if Airlock asks for recent authentication.',
    description: 'Security notice explaining the recent-authentication requirement.',
  },
  'auth.security.passkeys': {
    defaultMessage: 'Passkeys',
    description: 'Passkeys card heading on the security page.',
  },
  'auth.security.addPasskey': {
    defaultMessage: 'Add passkey',
    description: 'Button that opens passkey registration.',
  },
  'auth.security.passkeysDescription': {
    defaultMessage: 'Passkeys are the primary, phishing-resistant way to sign in. Add one per device.',
    description: 'Explanation of passkeys on the security page.',
  },
  'auth.security.noPasskeys': {
    defaultMessage: 'No passkeys yet. Add one to enable passwordless sign-in.',
    description: 'Empty state for the account passkeys table.',
  },
  'auth.security.name': {
    defaultMessage: 'Name',
    description: 'Passkey name column and field label.',
  },
  'auth.security.synced': {
    defaultMessage: 'synced',
    description: 'Badge indicating a passkey can be synchronized across devices.',
  },
  'auth.security.added': {
    defaultMessage: 'Added',
    description: 'Column heading for the date a passkey was added.',
  },
  'auth.security.lastUsed': {
    defaultMessage: 'Last used',
    description: 'Column heading for the most recent passkey or session use.',
  },
  'auth.security.password': {
    defaultMessage: 'Password',
    description: 'Password card heading on the security page.',
  },
  'auth.security.passwordDescription': {
    defaultMessage: 'Optional. A strong password is an alternative sign-in method; passkeys are preferred.',
    description: 'Explanation of optional password authentication.',
  },
  'auth.security.newPassword': {
    defaultMessage: 'New password',
    description: 'New-password field label on the security page.',
  },
  'auth.security.confirmPassword': {
    defaultMessage: 'Confirm password',
    description: 'Password-confirmation field label on the security page.',
  },
  'auth.security.changePassword': {
    defaultMessage: 'Change password',
    description: 'Button that changes an existing account password.',
  },
  'auth.security.setPassword': {
    defaultMessage: 'Set password',
    description: 'Button that sets an account password for the first time.',
  },
  'auth.security.sessions': {
    defaultMessage: 'Sessions',
    description: 'Account sessions card heading on the security page.',
  },
  'auth.security.sessionsDescription': {
    defaultMessage: 'Web and CLI sign-ins for your account. Revoking a session invalidates its access and refresh credentials immediately.',
    description: 'Explanation of account sessions and session revocation.',
  },
  'auth.security.loading': {
    defaultMessage: 'Loading…',
    description: 'Progress text while security-page data is loading.',
  },
  'auth.security.notAvailable': {
    defaultMessage: '-',
    description: 'Placeholder shown when a passkey date is unavailable.',
  },
  'auth.security.noSessions': {
    defaultMessage: 'No active sessions.',
    description: 'Empty state for the account sessions table.',
  },
  'auth.security.session': {
    defaultMessage: 'Session',
    description: 'Account session table column heading.',
  },
  'auth.security.kind': {
    defaultMessage: 'Kind',
    description: 'Column heading for the account session kind.',
  },
  'auth.security.sessionKind.web': {
    defaultMessage: 'Web',
    description: 'Display label for a web account session.',
  },
  'auth.security.sessionKind.cli': {
    defaultMessage: 'CLI',
    description: 'Display label for a command-line account session.',
  },
  'auth.security.sessionKind.telegram': {
    defaultMessage: 'Telegram',
    description: 'Display label for a Telegram account session; Telegram is a product name.',
  },
  'auth.security.expires': {
    defaultMessage: 'Expires',
    description: 'Column heading for session or OAuth grant expiration.',
  },
  'auth.security.revokeSession': {
    defaultMessage: 'Revoke session',
    description: 'Tooltip for the button that revokes an account session.',
  },
  'auth.security.authorizedApps': {
    defaultMessage: 'Authorized apps',
    description: 'OAuth grants card heading on the security page.',
  },
  'auth.security.authorizedAppsDescription': {
    defaultMessage: 'External MCP clients (Claude Desktop, VSCode, Codex, …) that you\'ve authorized to talk to your apps. Revoking immediately stops future requests; tokens already issued may keep working for up to 15 minutes until their access token naturally expires.',
    description: 'Explanation of authorized MCP clients; product names and MCP remain unchanged.',
  },
  'auth.security.noAuthorizedApps': {
    defaultMessage: 'No external apps are connected.',
    description: 'Empty state for authorized external apps.',
  },
  'auth.security.app': {
    defaultMessage: 'App',
    description: 'Authorized app and target app table column heading.',
  },
  'auth.security.appSlug': {
    defaultMessage: '({slug})',
    description: 'Unchanged app slug shown after an authorized app name.',
  },
  'auth.security.granted': {
    defaultMessage: 'Granted',
    description: 'Column heading for the date an OAuth grant was issued.',
  },
  'auth.security.revokeAccess': {
    defaultMessage: 'Revoke access',
    description: 'Tooltip for revoking an authorized app grant.',
  },
  'auth.security.linkedAccounts': {
    defaultMessage: 'Linked accounts',
    description: 'External identities card heading on the security page.',
  },
  'auth.security.allIdentitiesDescription': {
    defaultMessage: 'Every Telegram identity linked to a user in this tenant. Unlinking forces the user to re-run /auth in their bot to regain access.',
    description: 'Administrator explanation of tenant identity links; Telegram and /auth remain unchanged.',
  },
  'auth.security.ownIdentitiesDescription': {
    defaultMessage: 'Your Telegram identities - used by bridge bots to recognise you. Unlinking forces you to re-run /auth in the bot the next time you DM it.',
    description: 'User explanation of their identity links; Telegram and /auth remain unchanged.',
  },
  'auth.security.noTenantIdentities': {
    defaultMessage: 'No platform identities are linked in this tenant.',
    description: 'Administrator empty state for tenant identity links.',
  },
  'auth.security.noOwnIdentities': {
    defaultMessage: 'You have no linked platform identities.',
    description: 'User empty state for their external identity links.',
  },
  'auth.security.owner': {
    defaultMessage: 'Owner',
    description: 'Column heading for the owner of an external identity link.',
  },
  'auth.security.platform': {
    defaultMessage: 'Platform',
    description: 'Column heading for an unchanged external platform identifier.',
  },
  'auth.security.platformUserId': {
    defaultMessage: 'Platform user ID',
    description: 'Column heading for an unchanged external-platform user identifier.',
  },
  'auth.security.linked': {
    defaultMessage: 'Linked',
    description: 'Column heading for the date an external identity was linked.',
  },
  'auth.security.unlink': {
    defaultMessage: 'Unlink',
    description: 'Tooltip for unlinking an external identity.',
  },
  'auth.security.addPasskeyDialog': {
    defaultMessage: 'Add a passkey',
    description: 'Heading for the passkey registration dialog.',
  },
  'auth.security.passkeyNameHelp': {
    defaultMessage: 'Give this passkey a name so you can recognize the device later.',
    description: 'Instructions for naming a new passkey.',
  },
  'auth.security.passkeyNamePlaceholder': {
    defaultMessage: 'e.g. MacBook Touch ID',
    description: 'Example passkey name; MacBook and Touch ID are product names.',
  },
  'auth.security.renamePasskey': {
    defaultMessage: 'Rename passkey',
    description: 'Heading for the passkey rename dialog.',
  },
})
