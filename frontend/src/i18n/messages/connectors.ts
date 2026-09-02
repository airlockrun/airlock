import { defineMessages } from './define'

export const connectorMessages = defineMessages({
  'connectors.common.retry': {
    defaultMessage: 'Retry',
    description: 'Button label for retrying a failed connector request.',
  },
  'connectors.common.commands': {
    defaultMessage: 'Commands',
    description: 'Heading for commands published or required by a connector.',
  },
  'connectors.common.localDirectories': {
    defaultMessage: 'Local directories',
    description: 'Heading for local directories published or required by a connector.',
  },
  'connectors.common.noDescription': {
    defaultMessage: 'No description provided.',
    description: 'Fallback shown when a connector command or directory has no description.',
  },
  'connectors.common.required': {
    defaultMessage: 'Required',
    description: 'Badge shown for a required local connector setting.',
  },
  'connectors.common.none': {
    defaultMessage: 'None',
    description: 'Fallback shown when a connector-related list has no values.',
  },
  'connectors.common.readiness.ready': {
    defaultMessage: 'Ready',
    description: 'Connector readiness label indicating it can be used.',
  },
  'connectors.common.readiness.needsConfiguration': {
    defaultMessage: 'Needs local configuration',
    description: 'Connector readiness label indicating local configuration is required.',
  },
  'connectors.common.readiness.incompatibleProtocol': {
    defaultMessage: 'Protocol incompatible',
    description: 'Connector readiness label indicating an incompatible protocol.',
  },
  'connectors.common.readiness.unhealthy': {
    defaultMessage: 'Unhealthy',
    description: 'Connector readiness label indicating failed health checks.',
  },
  'connectors.common.readiness.starting': {
    defaultMessage: 'Starting',
    description: 'Connector readiness label indicating startup is in progress.',
  },
  'connectors.common.readiness.offline': {
    defaultMessage: 'Offline',
    description: 'Connector readiness label indicating the installation is offline.',
  },
  'connectors.common.readiness.unknown': {
    defaultMessage: 'Unknown',
    description: 'Fallback connector readiness label when no status was supplied.',
  },
  'connectors.common.access.read': {
    defaultMessage: 'read',
    description: 'Directory permission allowing a connector to read files.',
  },
  'connectors.common.access.write': {
    defaultMessage: 'write',
    description: 'Directory permission allowing a connector to write files.',
  },
  'connectors.common.access.list': {
    defaultMessage: 'list',
    description: 'Directory permission allowing a connector to list files.',
  },
  'connectors.common.capability.view': {
    defaultMessage: 'View',
    description: 'Localized label for the connector resource view capability.',
  },
  'connectors.common.capability.bind': {
    defaultMessage: 'Bind',
    description: 'Localized label for the connector resource bind capability.',
  },
  'connectors.common.capability.manage': {
    defaultMessage: 'Manage',
    description: 'Localized label for the connector resource manage capability.',
  },
  'connectors.tab.groupOption': {
    defaultMessage: '{name} ({ready}/{total} compatible and ready)',
    description: 'Target group option showing compatible ready installations and total members.',
  },
  'connectors.tab.compatible': {
    defaultMessage: 'Compatible',
    description: 'Label and explanation for a connector compatible with an app requirement.',
  },
  'connectors.tab.incompatible': {
    defaultMessage: 'Incompatible',
    description: 'Label for a connector incompatible with an app requirement.',
  },
  'connectors.tab.incompatibleReason': {
    defaultMessage: 'This resource does not satisfy the complete connector requirement.',
    description: 'Explanation for an existing connector that is not a compatible candidate.',
  },
  'connectors.tab.groupCreated': {
    defaultMessage: 'Connector target group created',
    description: 'Success toast after creating a connector target group.',
  },
  'connectors.tab.groupCreationFailed': {
    defaultMessage: 'Target group creation failed',
    description: 'Fallback error toast when target group creation fails.',
  },
  'connectors.tab.groupBound': {
    defaultMessage: 'Connector target group bound',
    description: 'Success toast after binding a connector target group to an app.',
  },
  'connectors.tab.groupBindingFailed': {
    defaultMessage: 'Target group binding failed',
    description: 'Fallback error toast when target group binding fails.',
  },
  'connectors.tab.disconnectConfirmTitle': {
    defaultMessage: 'Disconnect connector from this app?',
    description: 'Confirmation dialog title before disconnecting a connector from an app.',
  },
  'connectors.tab.thisInstallation': {
    defaultMessage: 'This installation',
    description: 'Fallback connector installation name in a disconnect confirmation.',
  },
  'connectors.tab.disconnectConfirmMessage': {
    defaultMessage: '{name} remains available to other apps. The installation and its local settings are not changed.',
    description: 'Confirmation message explaining the scope of disconnecting a connector.',
  },
  'connectors.tab.disconnect': {
    defaultMessage: 'Disconnect from this app',
    description: 'Button label for disconnecting a connector from the current app.',
  },
  'connectors.tab.cancel': {
    defaultMessage: 'Cancel',
    description: 'Button label for cancelling a connector action.',
  },
  'connectors.tab.disconnected': {
    defaultMessage: 'Connector disconnected from this app',
    description: 'Success toast after disconnecting a connector from an app.',
  },
  'connectors.tab.disconnectFailed': {
    defaultMessage: 'Disconnect failed',
    description: 'Fallback error toast when disconnecting a connector fails.',
  },
  'connectors.tab.appHandle': {
    defaultMessage: 'App handle:',
    description: 'Label preceding the stable app connector requirement slug.',
  },
  'connectors.tab.targetGroup': {
    defaultMessage: 'Target group',
    description: 'Badge and field label for a connector target group.',
  },
  'connectors.tab.singleInstallation': {
    defaultMessage: 'Single installation',
    description: 'Badge for an app requirement bound to one connector installation.',
  },
  'connectors.tab.bound': {
    defaultMessage: 'Bound',
    description: 'Badge indicating a connector requirement is bound.',
  },
  'connectors.tab.unbound': {
    defaultMessage: 'Unbound',
    description: 'Badge indicating a connector requirement is not bound.',
  },
  'connectors.tab.boundNotVisible': {
    defaultMessage: 'The bound connector is not visible with your current resource capabilities.',
    description: 'Warning when a bound connector is not visible to the current user.',
  },
  'connectors.tab.requiredContract': {
    defaultMessage: 'Required contract',
    description: 'Heading for the connector contract required by an app.',
  },
  'connectors.tab.args': {
    defaultMessage: 'Args:',
    description: 'Label for a required connector command input schema signature.',
  },
  'connectors.tab.returns': {
    defaultMessage: 'Returns:',
    description: 'Label for a required connector command output schema signature.',
  },
  'connectors.tab.noCommandsRequired': {
    defaultMessage: 'No commands required.',
    description: 'Message when an app connector contract requires no commands.',
  },
  'connectors.tab.noDirectoriesRequired': {
    defaultMessage: 'No local directories required.',
    description: 'Message when an app connector contract requires no local directories.',
  },
  'connectors.tab.targetGroupBinding': {
    defaultMessage: 'Target group binding',
    description: 'Label for the current connector target group binding.',
  },
  'connectors.tab.noTargetGroupSelected': {
    defaultMessage: 'No target group selected',
    description: 'Message when no connector target group is bound.',
  },
  'connectors.tab.existingResources': {
    defaultMessage: 'Existing resources',
    description: 'Heading for existing connector installations.',
  },
  'connectors.tab.compatibleCount': {
    defaultMessage: '{formattedCount} compatible',
    description: 'Count of existing connector resources compatible with an app requirement.',
  },
  'connectors.tab.noPublishedContract': {
    defaultMessage: 'No published contract',
    description: 'Fallback when a connector has not published a contract.',
  },
  'connectors.tab.appCount.one': {
    defaultMessage: '{formattedCount} app',
    description: 'Number of apps using a connector installation, for the locale one plural category.',
  },
  'connectors.tab.appCount.few': {
    defaultMessage: '{formattedCount} apps',
    description: 'Number of apps using a connector installation, for the locale few plural category.',
  },
  'connectors.tab.appCount.many': {
    defaultMessage: '{formattedCount} apps',
    description: 'Number of apps using a connector installation, for the locale many plural category.',
  },
  'connectors.tab.appCount.other': {
    defaultMessage: '{formattedCount} apps',
    description: 'Number of apps using a connector installation, for the locale other plural category.',
  },
  'connectors.tab.noInstallationsVisible': {
    defaultMessage: 'No connector installations are visible to you.',
    description: 'Message when no existing connector installation is visible.',
  },
  'connectors.tab.install': {
    defaultMessage: 'Install connector',
    description: 'Button and dialog title for installing a connector.',
  },
  'connectors.tab.installOnHost': {
    defaultMessage: 'Install on host',
    description: 'Button label for installing a connector on a managed host.',
  },
  'connectors.tab.update': {
    defaultMessage: 'Update',
    description: 'Button label for opening the managed connector update workflow.',
  },
  'connectors.tab.bindTargetGroup': {
    defaultMessage: 'Bind target group',
    description: 'Button label for binding a connector target group.',
  },
  'connectors.tab.bindExisting': {
    defaultMessage: 'Bind existing',
    description: 'Button label for binding an existing connector installation.',
  },
  'connectors.tab.switchTargetGroup': {
    defaultMessage: 'Switch target group',
    description: 'Button label for replacing a bound connector target group.',
  },
  'connectors.tab.switchResource': {
    defaultMessage: 'Switch resource',
    description: 'Button label for replacing a bound connector installation.',
  },
  'connectors.tab.viewOnly': {
    defaultMessage: 'View only',
    description: 'Label indicating the current user cannot modify connector bindings.',
  },
  'connectors.tab.yourAccess': {
    defaultMessage: 'Your resource access: {access}',
    description: 'Current user capabilities for a connector resource.',
  },
  'connectors.tab.noRequirements': {
    defaultMessage: 'No connector requirements registered.',
    description: 'Empty state when an app has no connector requirements.',
  },
  'connectors.tab.bindGroupTitle': {
    defaultMessage: 'Bind connector target group',
    description: 'Title of the dialog for binding a connector target group.',
  },
  'connectors.tab.chooseGroup': {
    defaultMessage: 'Choose an owned target group for {contractId}. The server requires at least one ready, compatible member.',
    description: 'Instructions for choosing a connector target group. contractId is shown as code.',
  },
  'connectors.tab.selectTargetGroup': {
    defaultMessage: 'Select a target group',
    description: 'Placeholder for the connector target group selector.',
  },
  'connectors.tab.noMatchingGroups': {
    defaultMessage: 'No owned target groups match this connector contract.',
    description: 'Message when no owned target group matches a connector contract.',
  },
  'connectors.tab.noUsableGroups': {
    defaultMessage: 'No target group currently has a ready member with bind access that satisfies the complete connector need.',
    description: 'Message when matching target groups have no eligible connector member.',
  },
  'connectors.tab.createTargetGroup': {
    defaultMessage: 'Create target group',
    description: 'Button label for starting connector target group creation.',
  },
  'connectors.tab.noAvailableGroupMembers': {
    defaultMessage: 'No ready compatible installations with bind access are available to populate a group.',
    description: 'Message when no connector installations can populate a target group.',
  },
  'connectors.tab.backToGroups': {
    defaultMessage: 'Back to target groups',
    description: 'Button label returning from target group creation to group selection.',
  },
  'connectors.tab.groupName': {
    defaultMessage: 'Group name',
    description: 'Label for a connector target group name.',
  },
  'connectors.tab.groupNamePlaceholder': {
    defaultMessage: 'e.g. Production machines',
    description: 'Example connector target group name.',
  },
  'connectors.tab.initialInstallations': {
    defaultMessage: 'Initial installations',
    description: 'Label for installations initially added to a connector target group.',
  },
  'connectors.tab.initialInstallationsHelp': {
    defaultMessage: 'Only ready installations that completely satisfy this app requirement are offered.',
    description: 'Help text for selecting initial connector target group members.',
  },
  'connectors.tab.createGroup': {
    defaultMessage: 'Create group',
    description: 'Button label for creating a connector target group.',
  },
  'connectors.store.error.loadFailed': {
    defaultMessage: 'Failed to load connectors',
    description: 'Fallback error when connector requirements and installations cannot be loaded.',
  },
  'connectors.install.error.unsupportedPlatform': {
    defaultMessage: 'Artifact file {artifactFileId} has unsupported platform {platform}.',
    description: 'Artifact validation error. artifactFileId and platform are exact technical values and must be preserved.',
  },
  'connectors.install.error.invalidInterface': {
    defaultMessage: 'Artifact set {artifactSetId} has an invalid interface.',
    description: 'Artifact validation error. artifactSetId is an exact technical value and must be preserved.',
  },
  'connectors.install.error.invalidSettings': {
    defaultMessage: 'Artifact set {artifactSetId} has invalid settings.',
    description: 'Artifact validation error. artifactSetId is an exact technical value and must be preserved.',
  },
  'connectors.install.error.unsupportedMacOSSystemServiceMode': {
    defaultMessage: 'Artifact set {artifactSetId} uses unsupported system service mode for macOS.',
    description: 'Artifact validation error for macOS system service mode. artifactSetId is an exact technical value and must be preserved.',
  },
  'connectors.settings.error.mustBeEnabled': {
    defaultMessage: 'This setting must be enabled.',
    description: 'Validation error for a required Boolean connector setting.',
  },
  'connectors.settings.error.signedInteger': {
    defaultMessage: 'Enter a signed 64-bit whole number.',
    description: 'Validation error for an invalid connector integer setting.',
  },
  'connectors.settings.error.nonZeroInteger': {
    defaultMessage: 'Enter a non-zero whole number.',
    description: 'Validation error for a required connector integer setting whose value is zero.',
  },
  'connectors.settings.error.duration': {
    defaultMessage: 'Enter a Go duration such as 5s or 1m30s.',
    description: 'Validation error for a connector duration. Preserve the Go duration examples exactly.',
  },
  'connectors.settings.error.nonZeroDuration': {
    defaultMessage: 'Enter a non-zero duration.',
    description: 'Validation error for a required connector duration whose value is zero.',
  },
  'connectors.settings.error.required': {
    defaultMessage: 'This setting is required.',
    description: 'Validation error for an empty required connector setting.',
  },
  'connectors.install.host.title': {
    defaultMessage: 'Install connector on a host',
    description: 'Title of the managed connector installation dialog.',
  },
  'connectors.install.host.description': {
    defaultMessage: 'Choose a managed host. Airlock selects the newest retained artifact built for that machine.',
    description: 'Instructions for selecting a host during connector installation.',
  },
  'connectors.install.host.manageRequired': {
    defaultMessage: 'Manage access is required.',
    description: 'Reason a host cannot be selected when the user lacks its manage capability.',
  },
  'connectors.install.host.updatesOnly': {
    defaultMessage: 'This host permits updates only.',
    description: 'Reason a host in update-only local access mode cannot accept a new connector installation.',
  },
  'connectors.install.host.managementDisabled': {
    defaultMessage: 'Remote management is disabled on this host.',
    description: 'Reason a host cannot accept managed connector installation.',
  },
  'connectors.install.host.stale': {
    defaultMessage: 'This host has not checked in recently.',
    description: 'Reason a stale host cannot accept managed connector installation.',
  },
  'connectors.install.host.noArtifact': {
    defaultMessage: 'No retained {platform} artifact is available.',
    description: 'Reason a host cannot be selected. platform is an exact operating-system and architecture identifier.',
  },
  'connectors.install.host.rebuildForSettings': {
    defaultMessage: 'Rebuild this app to publish typed settings metadata.',
    description: 'Reason installation is blocked when the connector artifact lacks typed setting field names.',
  },
  'connectors.install.host.loadFailed': {
    defaultMessage: 'Failed to load hosts and retained artifacts',
    description: 'Fallback error when managed hosts or connector artifacts cannot be loaded.',
  },
  'connectors.install.host.noneAvailable': {
    defaultMessage: 'No hosts are available. Enroll a host from Resources before installing this connector.',
    description: 'Empty state in the connector installation dialog when no managed hosts are visible.',
  },
  'connectors.install.host.selectionLabel': {
    defaultMessage: 'Installation host',
    description: 'Accessible label for the managed host selection list.',
  },
  'connectors.install.host.connectorCount.one': {
    defaultMessage: '{formattedCount} connector',
    description: 'Number of connectors installed on a host, for the locale one plural category.',
  },
  'connectors.install.host.connectorCount.few': {
    defaultMessage: '{formattedCount} connectors',
    description: 'Number of connectors installed on a host, for the locale few plural category.',
  },
  'connectors.install.host.connectorCount.many': {
    defaultMessage: '{formattedCount} connectors',
    description: 'Number of connectors installed on a host, for the locale many plural category.',
  },
  'connectors.install.host.connectorCount.other': {
    defaultMessage: '{formattedCount} connectors',
    description: 'Number of connectors installed on a host, for the locale other plural category.',
  },
  'connectors.install.host.installationName': {
    defaultMessage: 'Installation name',
    description: 'Label for the display name assigned to a managed connector installation.',
  },
  'connectors.install.host.settings': {
    defaultMessage: 'Connector settings',
    description: 'Heading for connector settings sent securely to a managed host.',
  },
  'connectors.install.host.selectValue': {
    defaultMessage: 'Select a value',
    description: 'Placeholder for an enumerated connector setting.',
  },
  'connectors.install.host.installingOn': {
    defaultMessage: 'Installing on {host}',
    description: 'Success toast summary after queuing installation. host is the user-visible host name.',
  },
  'connectors.install.host.workQueued': {
    defaultMessage: 'Management work has been queued.',
    description: 'Success toast detail after queuing managed connector work.',
  },
  'connectors.install.host.failed': {
    defaultMessage: 'Connector installation failed',
    description: 'Fallback error when managed connector installation cannot be queued.',
  },
  'connectors.install.host.installConnector': {
    defaultMessage: 'Install connector',
    description: 'Submit button for queuing a connector installation on the selected host.',
  },
  'connectors.update.title': {
    defaultMessage: 'Update connector',
    description: 'Title of the managed connector update dialog.',
  },
  'connectors.update.description': {
    defaultMessage: 'Updates require Agent admin access and Manage access to the connector host.',
    description: 'Explanation of the two authorization requirements for updating a managed connector.',
  },
  'connectors.update.agentAdminRequired': {
    defaultMessage: 'Agent admin access is required to discover and update connector artifacts.',
    description: 'Reason a connector update is blocked when the user is not an administrator of the app.',
  },
  'connectors.update.hostUnavailable': {
    defaultMessage: 'The connector host is not available to you.',
    description: 'Reason a connector update is blocked when its host is not visible to the user.',
  },
  'connectors.update.manageRequired': {
    defaultMessage: 'Manage access to this host is required.',
    description: 'Reason a connector update is blocked when the user lacks the host manage capability.',
  },
  'connectors.update.disabled': {
    defaultMessage: 'Remote updates are disabled on this host.',
    description: 'Reason a connector update is blocked by the host-reported local access mode.',
  },
  'connectors.update.noArtifact': {
    defaultMessage: 'No compatible retained {platform} artifact is available.',
    description: 'Reason a connector update is blocked. platform is an exact operating-system and architecture identifier.',
  },
  'connectors.update.loadFailed': {
    defaultMessage: 'Failed to load retained update artifacts',
    description: 'Fallback error when retained artifacts for a connector update cannot be loaded.',
  },
  'connectors.update.retainedVersion': {
    defaultMessage: 'Retained version',
    description: 'Label for selecting a retained connector artifact version.',
  },
  'connectors.update.artifactDigest': {
    defaultMessage: '{filename} · SHA-256 {sha256}',
    description: 'Selected connector artifact filename and digest. Preserve filename, SHA-256, and sha256 exactly.',
  },
  'connectors.update.replaceSettings': {
    defaultMessage: 'Replace connector settings',
    description: 'Checkbox label for replacing all local connector settings during an update.',
  },
  'connectors.update.retainSettings': {
    defaultMessage: 'Leave this off to retain all current settings, including secrets. Secret values are never returned to the browser.',
    description: 'Explanation that settings and secrets are retained unless explicitly replaced during an update.',
  },
  'connectors.update.updating': {
    defaultMessage: 'Updating {connector}',
    description: 'Success toast summary after queuing a connector update. connector is the user-visible connector name.',
  },
  'connectors.update.failed': {
    defaultMessage: 'Connector update failed',
    description: 'Fallback error when a managed connector update cannot be queued.',
  },
  'connectors.update.queue': {
    defaultMessage: 'Queue update',
    description: 'Submit button for queuing a managed connector update.',
  },
  'connectors.host.status.ready': {
    defaultMessage: 'Ready',
    description: 'Status label for a managed host that checked in recently.',
  },
  'connectors.host.status.stale': {
    defaultMessage: 'Stale',
    description: 'Status label for a managed host that has not checked in recently.',
  },
  'connectors.host.status.revoked': {
    defaultMessage: 'Revoked',
    description: 'Status label for a revoked managed host.',
  },
  'connectors.host.access.full': {
    defaultMessage: 'Full management',
    description: 'Display label for a host that permits all remote management actions.',
  },
  'connectors.host.access.updateOnly': {
    defaultMessage: 'Update only',
    description: 'Display label for a host that permits connector updates and rollbacks only.',
  },
  'connectors.host.access.none': {
    defaultMessage: 'Management disabled',
    description: 'Display label for a host that permits no remote management actions.',
  },
  'connectors.host.detail.loadFailed': {
    defaultMessage: 'Failed to load host',
    description: 'Fallback error when managed host details cannot be loaded.',
  },
  'connectors.host.detail.owner': {
    defaultMessage: 'Owner',
    description: 'Label for the owner of a managed host.',
  },
  'connectors.host.detail.yourAccess': {
    defaultMessage: 'Your access',
    description: 'Label for the current user capabilities on a managed host.',
  },
  'connectors.host.detail.accessExplanation': {
    defaultMessage: 'Local access is reported by this host. Airlock cannot change it. Connector domain commands remain available in every mode.',
    description: 'Explanation of host-reported local access and connector command availability.',
  },
  'connectors.host.detail.staleWarning': {
    defaultMessage: 'This host has not checked in recently. Management actions are unavailable until it reconnects.',
    description: 'Warning shown when a managed host is stale.',
  },
  'connectors.host.detail.shell': {
    defaultMessage: 'Shell',
    description: 'Button label for opening the managed host shell request dialog.',
  },
  'connectors.host.detail.hostedConnectors': {
    defaultMessage: 'Hosted connectors',
    description: 'Heading for connectors installed on a managed host.',
  },
  'connectors.host.detail.noConnectors': {
    defaultMessage: 'No connectors are installed on this host.',
    description: 'Empty state for a host with no connector installations.',
  },
  'connectors.host.detail.connector': {
    defaultMessage: 'Connector',
    description: 'Column heading for a connector installed on a host.',
  },
  'connectors.host.detail.version': {
    defaultMessage: 'Version',
    description: 'Column heading for a host or connector version.',
  },
  'connectors.host.detail.readiness': {
    defaultMessage: 'Readiness',
    description: 'Column heading for connector readiness on a host.',
  },
  'connectors.host.detail.rollback': {
    defaultMessage: 'Rollback',
    description: 'Button label for rolling back a hosted connector.',
  },
  'connectors.host.detail.remove': {
    defaultMessage: 'Remove',
    description: 'Button label for removing a hosted connector.',
  },
  'connectors.host.detail.managementHistory': {
    defaultMessage: 'Management history',
    description: 'Heading for host management job history.',
  },
  'connectors.host.detail.noManagementRequests': {
    defaultMessage: 'No management requests yet.',
    description: 'Empty state for host management job history.',
  },
  'connectors.host.detail.kind': {
    defaultMessage: 'Kind',
    description: 'Column heading for the kind of host management request.',
  },
  'connectors.host.detail.status': {
    defaultMessage: 'Status',
    description: 'Column heading for host management request status.',
  },
  'connectors.host.detail.result': {
    defaultMessage: 'Result',
    description: 'Column heading for a host management request result.',
  },
  'connectors.host.detail.managementKind.shell': {
    defaultMessage: 'Shell command',
    description: 'Kind label for a host management job that runs a shell command.',
  },
  'connectors.host.detail.managementKind.connectorInstall': {
    defaultMessage: 'Install connector',
    description: 'Kind label for a host management job that installs a connector.',
  },
  'connectors.host.detail.managementKind.connectorUpdate': {
    defaultMessage: 'Update connector',
    description: 'Kind label for a host management job that updates a connector.',
  },
  'connectors.host.detail.managementKind.connectorRemove': {
    defaultMessage: 'Remove connector',
    description: 'Kind label for a host management job that removes a connector.',
  },
  'connectors.host.detail.managementKind.connectorRollback': {
    defaultMessage: 'Rollback connector',
    description: 'Kind label for a host management job that rolls back a connector.',
  },
  'connectors.host.detail.managementStatus.queued': {
    defaultMessage: 'Queued',
    description: 'Status label for a host management job waiting to run.',
  },
  'connectors.host.detail.managementStatus.running': {
    defaultMessage: 'Running',
    description: 'Status label for a host management job in progress.',
  },
  'connectors.host.detail.managementStatus.succeeded': {
    defaultMessage: 'Succeeded',
    description: 'Status label for a successful host management job.',
  },
  'connectors.host.detail.managementStatus.failed': {
    defaultMessage: 'Failed',
    description: 'Status label for a failed host management job.',
  },
  'connectors.host.detail.managementStatus.cancelled': {
    defaultMessage: 'Cancelled',
    description: 'Status label for a cancelled host management job.',
  },
  'connectors.host.detail.managementStatus.timedOut': {
    defaultMessage: 'Timed out',
    description: 'Status label for a host management job that exceeded its deadline.',
  },
  'connectors.host.detail.runShellCommand': {
    defaultMessage: 'Run shell command',
    description: 'Title of the managed host shell request dialog.',
  },
  'connectors.host.detail.executable': {
    defaultMessage: 'Executable',
    description: 'Label for an exact executable path in a host shell request.',
  },
  'connectors.host.detail.argumentsJson': {
    defaultMessage: 'Arguments JSON',
    description: 'Label for the JSON string array of host shell command arguments. Preserve JSON as a technical term.',
  },
  'connectors.host.detail.queueRequest': {
    defaultMessage: 'Queue request',
    description: 'Button label for queuing a host shell request.',
  },
  'connectors.host.detail.argumentsInvalid': {
    defaultMessage: 'Arguments must be a JSON string array',
    description: 'Validation error for host shell arguments. Preserve JSON as a technical term.',
  },
  'connectors.host.detail.workQueued': {
    defaultMessage: 'Management work queued',
    description: 'Success toast after queuing a host shell request.',
  },
  'connectors.host.detail.requestFailed': {
    defaultMessage: 'Request failed',
    description: 'Fallback error when a host shell request cannot be queued.',
  },
  'connectors.host.detail.removalQueued': {
    defaultMessage: 'Removal queued',
    description: 'Success toast after queuing hosted connector removal.',
  },
  'connectors.host.detail.removalFailed': {
    defaultMessage: 'Removal failed',
    description: 'Fallback error when hosted connector removal cannot be queued.',
  },
  'connectors.host.detail.rollbackQueued': {
    defaultMessage: 'Rollback queued',
    description: 'Success toast after queuing hosted connector rollback.',
  },
  'connectors.host.detail.rollbackFailed': {
    defaultMessage: 'Rollback failed',
    description: 'Fallback error when hosted connector rollback cannot be queued.',
  },
  'connectors.enrollment.title': {
    defaultMessage: 'Enroll airlock-host',
    description: 'Title of the host enrollment page. Preserve airlock-host exactly.',
  },
  'connectors.enrollment.subtitle': {
    defaultMessage: 'Enter the one-time code shown by the host. Every enrollment creates a distinct host identity.',
    description: 'Instructions for beginning managed host enrollment.',
  },
  'connectors.enrollment.inspect': {
    defaultMessage: 'Inspect',
    description: 'Button label for inspecting a one-time host enrollment code.',
  },
  'connectors.enrollment.notFound': {
    defaultMessage: 'Enrollment not found',
    description: 'Fallback error when a host enrollment code cannot be inspected.',
  },
  'connectors.enrollment.approved': {
    defaultMessage: 'Host enrollment approved',
    description: 'Success toast after approving host enrollment.',
  },
  'connectors.enrollment.approvalFailed': {
    defaultMessage: 'Approval failed',
    description: 'Fallback error when host enrollment cannot be approved.',
  },
  'connectors.enrollment.denialFailed': {
    defaultMessage: 'Denial failed',
    description: 'Fallback error when host enrollment cannot be denied.',
  },
  'connectors.enrollment.status': {
    defaultMessage: 'Status: {status}',
    description: 'Host enrollment status. status is a localized status label.',
  },
  'connectors.enrollment.status.pending': {
    defaultMessage: 'Pending',
    description: 'Status label for a host enrollment awaiting a decision.',
  },
  'connectors.enrollment.status.approved': {
    defaultMessage: 'Approved',
    description: 'Status label for an approved host enrollment.',
  },
  'connectors.enrollment.status.denied': {
    defaultMessage: 'Denied',
    description: 'Status label for a denied host enrollment.',
  },
  'connectors.enrollment.status.consumed': {
    defaultMessage: 'Completed',
    description: 'Status label for a host enrollment whose credential was consumed.',
  },
  'connectors.enrollment.status.expired': {
    defaultMessage: 'Expired',
    description: 'Status label for an expired host enrollment.',
  },
  'connectors.enrollment.name': {
    defaultMessage: 'Name',
    description: 'Label for the host name reported during enrollment.',
  },
  'connectors.enrollment.platform': {
    defaultMessage: 'Platform',
    description: 'Label for the host platform and architecture reported during enrollment.',
  },
  'connectors.enrollment.reportedAccess': {
    defaultMessage: 'Reported access',
    description: 'Label for local management access reported by an enrolling host.',
  },
  'connectors.enrollment.version': {
    defaultMessage: 'Version',
    description: 'Label for the airlock-host version reported during enrollment.',
  },
  'connectors.enrollment.deny': {
    defaultMessage: 'Deny',
    description: 'Button label for denying host enrollment.',
  },
  'connectors.enrollment.approve': {
    defaultMessage: 'Approve',
    description: 'Button label for approving host enrollment.',
  },
})
