import { defineMessages } from './define'

export const operationMessages = defineMessages({
  'operations.common.cancel': {
    defaultMessage: 'Cancel',
    description: 'Button label that dismisses an operations confirmation dialog.',
  },
  'operations.common.error': {
    defaultMessage: 'Error',
    description: 'Generic error toast title in operations screens.',
  },
  'operations.common.loadMore': {
    defaultMessage: 'Load More',
    description: 'Button label that loads another page of operation records.',
  },
  'operations.common.unknown': {
    defaultMessage: 'Unknown',
    description: 'Fallback label when an operation source is unknown.',
  },
  'operations.common.unknownError': {
    defaultMessage: 'unknown error',
    description: 'Fallback error detail when an operation failure has no message.',
  },
  'operations.build.title': {
    defaultMessage: '{agent} · Build {id}',
    description: 'Build detail page title. Agent is an agent name and id is a shortened build ID.',
  },
  'operations.build.cancel': {
    defaultMessage: 'Cancel build',
    description: 'Button label for cancelling an in-progress build.',
  },
  'operations.build.cancelled': {
    defaultMessage: 'Build cancelled',
    description: 'Toast title after a build is cancelled.',
  },
  'operations.build.cancelFailed': {
    defaultMessage: 'Cancel failed',
    description: 'Toast title when cancelling a build or background job fails.',
  },
  'operations.build.tasksProgress': {
    defaultMessage: '{doneFormatted}/{countFormatted} task | {doneFormatted}/{countFormatted} tasks',
    description: 'Build task progress. DoneFormatted and countFormatted are localized counts; count controls pluralization.',
  },
  'operations.build.tokens': {
    defaultMessage: '{input} in / {output} out tokens',
    description: 'Build or run token usage without cached input tokens.',
  },
  'operations.build.tokensCached': {
    defaultMessage: '{input} in + {cached} cached / {output} out tokens',
    description: 'Build or run token usage including cached input tokens.',
  },
  'operations.build.phase.deploymentBlocked': {
    defaultMessage: 'Deployment blocked by incompatible jobs',
    description: 'Build phase label when incompatible jobs prevent deployment.',
  },
  'operations.build.phase.draining': {
    defaultMessage: 'Draining active jobs…',
    description: 'Build phase label while active jobs are draining.',
  },
  'operations.build.phase.starting': {
    defaultMessage: 'Starting candidate runtime…',
    description: 'Build phase label while the candidate runtime starts.',
  },
  'operations.build.phase.rollback': {
    defaultMessage: 'Rolling back deployment…',
    description: 'Build phase label while a failed candidate deployment is rolled back.',
  },
  'operations.build.phase.manifest': {
    defaultMessage: 'Checking job compatibility…',
    description: 'Build phase label while job compatibility is checked.',
  },
  'operations.build.phase.image': {
    defaultMessage: 'Building image…',
    description: 'Build phase label while a container image is built.',
  },
  'operations.build.phase.connectors': {
    defaultMessage: 'Building connectors…',
    description: 'Build phase label while connector artifacts are built.',
  },
  'operations.build.phase.migrations': {
    defaultMessage: 'Running migrations…',
    description: 'Build phase label while database migrations run.',
  },
  'operations.build.phase.deploy': {
    defaultMessage: 'Deploying…',
    description: 'Build phase label while an app is deployed.',
  },
  'operations.build.phase.codegen': {
    defaultMessage: 'Generating code…',
    description: 'Build phase label while app code is generated.',
  },
  'operations.build.phase.building': {
    defaultMessage: 'Building…',
    description: 'Generic build-in-progress phase label.',
  },
  'operations.build.phase.buildingTasks': {
    defaultMessage: 'Building {doneFormatted}/{countFormatted} task | Building {doneFormatted}/{countFormatted} tasks',
    description: 'Build badge with localized completed and total task counts. Count controls pluralization.',
  },
  'operations.build.deployment.blocked': {
    defaultMessage: 'The candidate cannot accept {formattedCount} queued or running job. Cancel jobs individually or wait for them to finish. | The candidate cannot accept {formattedCount} queued or running jobs. Cancel jobs individually or wait for them to finish.',
    description: 'Explanation shown when one or more jobs block candidate deployment. FormattedCount is localized; count controls pluralization.',
  },
  'operations.build.deployment.paused': {
    defaultMessage: 'New dispatch is paused while active attempts drain. The drain window is fixed at two minutes.',
    description: 'Explanation shown while deployment waits for active job attempts to drain.',
  },
  'operations.build.deployment.starting': {
    defaultMessage: 'The drain completed and Airlock is switching to the candidate runtime.',
    description: 'Explanation shown while deployment switches to the candidate runtime.',
  },
  'operations.build.deployment.rollback': {
    defaultMessage: 'The candidate did not start successfully. Airlock is restoring the previous runtime.',
    description: 'Explanation shown while deployment restores the prior runtime.',
  },
  'operations.build.deployment.drainingStatus': {
    defaultMessage: 'draining',
    description: 'Status tag shown while active jobs drain before deployment.',
  },
  'operations.build.deployment.pausedAt': {
    defaultMessage: 'Paused {time}',
    description: 'Build deployment drain start time.',
  },
  'operations.build.deployment.deadline': {
    defaultMessage: 'Deadline {time}',
    description: 'Build deployment drain deadline.',
  },
  'operations.build.deployment.remaining': {
    defaultMessage: '{time} remaining',
    description: 'Time remaining in the deployment drain window.',
  },
  'operations.build.blockers.queued': {
    defaultMessage: '{count} queued',
    description: 'Number of queued jobs blocking a deployment.',
  },
  'operations.build.blockers.running': {
    defaultMessage: '{count} running',
    description: 'Number of running jobs blocking a deployment.',
  },
  'operations.build.blockers.inputSchema': {
    defaultMessage: 'Input schema',
    description: 'Label for the input schema hash of a blocking job contract.',
  },
  'operations.build.blockers.outputSchema': {
    defaultMessage: 'Output schema',
    description: 'Label for the output schema hash of a blocking job contract.',
  },
  'operations.build.blockers.heading': {
    defaultMessage: 'Blocking jobs',
    description: 'Heading above jobs that block a deployment.',
  },
  'operations.build.blockers.cancelTitle': {
    defaultMessage: 'Cancel blocking job?',
    description: 'Confirmation title before cancelling a job that blocks deployment.',
  },
  'operations.build.blockers.cancelMessage': {
    defaultMessage: 'Cancel {handler}@v{version}? This explicitly cancels only job {id}.',
    description: 'Confirmation text for cancelling one blocking job. Handler, version, and id identify the job.',
  },
  'operations.build.blockers.cancelJob': {
    defaultMessage: 'Cancel job',
    description: 'Confirmation button label for cancelling a background job.',
  },
  'operations.build.blockers.keepJob': {
    defaultMessage: 'Keep job',
    description: 'Confirmation button label that leaves a blocking job running.',
  },
  'operations.build.blockers.cancellationRequested': {
    defaultMessage: 'Cancellation requested',
    description: 'Toast title after cancellation is requested for a running job.',
  },
  'operations.build.blockers.jobCancelled': {
    defaultMessage: 'Job cancelled',
    description: 'Toast title after a queued job is cancelled.',
  },
  'operations.build.blockers.loadMore': {
    defaultMessage: 'Load more blocking jobs',
    description: 'Button label that loads more jobs blocking deployment.',
  },
  'operations.build.platformError': {
    defaultMessage: 'Platform error',
    description: 'Label for a build failure caused by Airlock infrastructure.',
  },
  'operations.build.platformErrorDetail': {
    defaultMessage: "Platform error - a build infrastructure failure (toolserver / docker / deploy), not a problem in your app's code. Retry the build; if it persists, check the Airlock logs.",
    description: 'Detailed guidance shown for a build infrastructure failure.',
  },
  'operations.build.platformErrorTooltip': {
    defaultMessage: "A build infrastructure failure (toolserver/docker/deploy), not your app's code.",
    description: 'Tooltip explaining a platform-error label in the builds table.',
  },
  'operations.build.instructions': {
    defaultMessage: 'Instructions',
    description: 'Heading above build instructions supplied by the user.',
  },
  'operations.build.tasks': {
    defaultMessage: 'Tasks ({doneFormatted}/{countFormatted})',
    description: 'Heading above a build task checklist with localized completed and total counts.',
  },
  'operations.build.codegenLog': {
    defaultMessage: 'Codegen log',
    description: 'Heading above the code-generation log.',
  },
  'operations.build.waitingForOutput': {
    defaultMessage: 'Waiting for build output…',
    description: 'Placeholder shown before build log output arrives.',
  },
  'operations.build.dockerLog': {
    defaultMessage: 'Docker build log',
    description: 'Heading above the Docker build log.',
  },
  'operations.build.list.empty': {
    defaultMessage: 'No builds yet.',
    description: 'Empty-state text for the builds table.',
  },
  'operations.build.list.type': {
    defaultMessage: 'Type',
    description: 'Builds table column heading for build type.',
  },
  'operations.build.list.description': {
    defaultMessage: 'Description',
    description: 'Builds table column heading for build instructions or rollback target.',
  },
  'operations.build.list.status': {
    defaultMessage: 'Status',
    description: 'Operations table column heading for status.',
  },
  'operations.build.list.result': {
    defaultMessage: 'Result',
    description: 'Builds table column heading for build results.',
  },
  'operations.build.list.started': {
    defaultMessage: 'Started',
    description: 'Operations table column heading or metadata label for start time.',
  },
  'operations.build.list.model': {
    defaultMessage: 'Model',
    description: 'Builds table column heading for the model used by code generation.',
  },
  'operations.build.list.cost': {
    defaultMessage: 'Cost',
    description: 'Operations table column heading for estimated LLM cost.',
  },
  'operations.build.list.finished': {
    defaultMessage: 'Finished',
    description: 'Builds table column heading for finish time.',
  },
  'operations.build.list.rolledBackTo': {
    defaultMessage: 'Rolled back to {target}',
    description: 'Build description for a rollback. Target is a shortened source revision or build ID.',
  },
  'operations.build.list.rolledBackDeleted': {
    defaultMessage: 'Rolled back (target deleted)',
    description: 'Build description when the target of a rollback no longer exists.',
  },
  'operations.build.rollback.title': {
    defaultMessage: 'Roll back to {target}?',
    description: 'Confirmation title before rolling back to a source revision.',
  },
  'operations.build.rollback.message': {
    defaultMessage: 'This reverses the app to a previous build. Migrations will be down-applied - data added by newer migrations may be lost. Forward commits stay reachable via a pre-rollback branch. Continue?',
    description: 'Warning shown before an app rollback.',
  },
  'operations.build.rollback.accept': {
    defaultMessage: 'Roll back',
    description: 'Confirmation button label that starts an app rollback.',
  },
  'operations.build.rollback.button': {
    defaultMessage: 'Rollback',
    description: 'Builds table action button label for rolling back to a build.',
  },
  'operations.build.rollback.started': {
    defaultMessage: 'Rollback started',
    description: 'Toast title after an app rollback starts.',
  },
  'operations.build.rollback.watchProgress': {
    defaultMessage: 'Watch the builds list for progress.',
    description: 'Toast detail directing the user to rollback progress.',
  },
  'operations.build.rollback.failed': {
    defaultMessage: 'Rollback failed to start',
    description: 'Toast title when an app rollback cannot be started.',
  },
  'operations.build.type.build': {
    defaultMessage: 'build',
    description: 'Build type status label for an initial app build.',
  },
  'operations.build.type.upgrade': {
    defaultMessage: 'upgrade',
    description: 'Build type status label for an app upgrade.',
  },
  'operations.build.type.rollback': {
    defaultMessage: 'rollback',
    description: 'Build type status label for an app rollback.',
  },
  'operations.build.status.building': {
    defaultMessage: 'building',
    description: 'Build status label while a build is in progress.',
  },
  'operations.build.status.complete': {
    defaultMessage: 'complete',
    description: 'Build status label for a completed build.',
  },
  'operations.build.status.failed': {
    defaultMessage: 'failed',
    description: 'Build status label for a failed build.',
  },
  'operations.build.status.refused': {
    defaultMessage: 'refused',
    description: 'Build status label when a build request is outside scope.',
  },
  'operations.build.status.cancelled': {
    defaultMessage: 'cancelled',
    description: 'Build status label for a cancelled build.',
  },
  'operations.job.title': {
    defaultMessage: '{agent} · Job {id}',
    description: 'Job detail page title. Agent is an agent name and id is a shortened job ID.',
  },
  'operations.job.cancel.title': {
    defaultMessage: 'Cancel background job?',
    description: 'Confirmation title before cancelling a background job.',
  },
  'operations.job.cancel.message': {
    defaultMessage: 'Cancel {handler}@v{version}? A running handler may take a moment to stop.',
    description: 'Confirmation text before cancelling a background job. Handler and version identify its handler.',
  },
  'operations.job.cancel.keepRunning': {
    defaultMessage: 'Keep running',
    description: 'Confirmation button label that leaves a background job running.',
  },
  'operations.job.cancel.button': {
    defaultMessage: 'Cancel job',
    description: 'Button label for cancelling a background job.',
  },
  'operations.job.cancel.action': {
    defaultMessage: 'Cancel',
    description: 'Compact table action for cancelling a background job.',
  },
  'operations.job.retry.button': {
    defaultMessage: 'Retry job',
    description: 'Button label for retrying a background job.',
  },
  'operations.job.retry.action': {
    defaultMessage: 'Retry',
    description: 'Compact table action for retrying a background job.',
  },
  'operations.job.retry.queued': {
    defaultMessage: 'Job queued for retry',
    description: 'Toast title after a background job is queued for retry.',
  },
  'operations.job.retry.failed': {
    defaultMessage: 'Retry failed',
    description: 'Toast title when retrying a background job fails.',
  },
  'operations.job.notFound': {
    defaultMessage: 'Job not found',
    description: 'Toast title when a requested background job does not exist.',
  },
  'operations.job.loadFailed': {
    defaultMessage: 'Jobs could not be loaded',
    description: 'Toast title when the background jobs list cannot be loaded.',
  },
  'operations.job.response.missingJob': {
    defaultMessage: 'The job response did not include a job.',
    description: 'Error detail when a successful job-detail response has no job payload.',
  },
  'operations.job.response.retryMissingJob': {
    defaultMessage: 'The retry response did not include a job.',
    description: 'Error detail when a successful job-retry response has no job payload.',
  },
  'operations.job.attemptsUsed': {
    defaultMessage: '{usedFormatted}/{limitFormatted} attempt used | {usedFormatted}/{limitFormatted} attempts used',
    description: 'Localized number of attempts consumed from a job attempt limit. Count controls pluralization.',
  },
  'operations.job.progress': {
    defaultMessage: 'Progress',
    description: 'Heading or table column for background job progress.',
  },
  'operations.job.working': {
    defaultMessage: 'Working',
    description: 'Fallback progress phase while a background job is working.',
  },
  'operations.job.progressAttempt': {
    defaultMessage: 'Attempt {formattedAttempt}',
    description: 'Current background job attempt number, formatted for the active locale.',
  },
  'operations.job.progressUpdated': {
    defaultMessage: 'updated {time}',
    description: 'Time at which background job progress was updated.',
  },
  'operations.job.metadata': {
    defaultMessage: 'Metadata and provenance',
    description: 'Heading above background job metadata and provenance.',
  },
  'operations.job.metadata.jobId': {
    defaultMessage: 'Job ID',
    description: 'Background job metadata label for its ID.',
  },
  'operations.job.metadata.agentId': {
    defaultMessage: 'Agent ID',
    description: 'Background job metadata label for its agent ID.',
  },
  'operations.job.metadata.source': {
    defaultMessage: 'Source',
    description: 'Background job metadata label for its source.',
  },
  'operations.job.metadata.cronId': {
    defaultMessage: 'Cron ID',
    description: 'Background job metadata label for its cron schedule ID.',
  },
  'operations.job.metadata.sourceRun': {
    defaultMessage: 'Source run',
    description: 'Background job metadata label for the run that created it.',
  },
  'operations.job.metadata.initiatorAccess': {
    defaultMessage: 'Initiator access',
    description: 'Background job metadata label for the initiator access level.',
  },
  'operations.job.metadata.initiatorUser': {
    defaultMessage: 'Initiator user',
    description: 'Background job metadata label for the initiating user ID.',
  },
  'operations.job.metadata.configuredAttempts': {
    defaultMessage: 'Configured attempts',
    description: 'Background job metadata label for configured maximum attempts.',
  },
  'operations.job.metadata.attemptLimit': {
    defaultMessage: 'Current attempt limit',
    description: 'Background job metadata label for its current attempt limit.',
  },
  'operations.job.metadata.timeout': {
    defaultMessage: 'Timeout',
    description: 'Background job metadata label for its timeout.',
  },
  'operations.job.metadata.timeoutMs': {
    defaultMessage: '{value} ms',
    description: 'Background job timeout in milliseconds.',
  },
  'operations.job.metadata.stateVersion': {
    defaultMessage: 'State version',
    description: 'Background job metadata label for its internal state version.',
  },
  'operations.job.metadata.scheduled': {
    defaultMessage: 'Scheduled',
    description: 'Background job metadata label for scheduled time.',
  },
  'operations.job.metadata.nextAttempt': {
    defaultMessage: 'Next attempt',
    description: 'Background job metadata label for its next attempt time.',
  },
  'operations.job.metadata.created': {
    defaultMessage: 'Created',
    description: 'Operations metadata label for creation time.',
  },
  'operations.job.metadata.updated': {
    defaultMessage: 'Updated',
    description: 'Operations metadata label for update time.',
  },
  'operations.job.metadata.started': {
    defaultMessage: 'Started',
    description: 'Operations metadata label for start time.',
  },
  'operations.job.metadata.completed': {
    defaultMessage: 'Completed',
    description: 'Operations metadata label for completion time.',
  },
  'operations.job.metadata.cancellationRequested': {
    defaultMessage: 'Cancellation requested',
    description: 'Background job metadata label for its cancellation request time.',
  },
  'operations.job.input': {
    defaultMessage: 'Input',
    description: 'Heading above background job input JSON.',
  },
  'operations.job.output': {
    defaultMessage: 'Output',
    description: 'Heading above background job output JSON.',
  },
  'operations.job.attempts': {
    defaultMessage: 'Attempts',
    description: 'Heading or table column for background job attempts.',
  },
  'operations.job.attempts.empty': {
    defaultMessage: 'No attempts yet.',
    description: 'Empty-state text for the background job attempts table.',
  },
  'operations.job.attempts.status': {
    defaultMessage: 'Status',
    description: 'Background job attempts table column for attempt status.',
  },
  'operations.job.attempts.run': {
    defaultMessage: 'Run',
    description: 'Background job attempts table column for the associated run.',
  },
  'operations.job.attempts.runtime': {
    defaultMessage: 'Runtime',
    description: 'Background job attempts table column for runtime generation.',
  },
  'operations.job.attempts.leased': {
    defaultMessage: 'Leased',
    description: 'Background job attempts table column for lease time.',
  },
  'operations.job.attempts.leaseExpires': {
    defaultMessage: 'Lease Expires',
    description: 'Background job attempts table column for lease expiry time.',
  },
  'operations.job.attempts.error': {
    defaultMessage: 'Error',
    description: 'Background job attempts table column for error details.',
  },
  'operations.job.source.cron': {
    defaultMessage: 'Cron {slug}',
    description: 'Background job source description. Slug is the cron schedule slug.',
  },
  'operations.job.source.cronList': {
    defaultMessage: 'Cron: {slug}',
    description: 'Compact background job source label. Slug is the cron schedule slug.',
  },
  'operations.job.initiator.user': {
    defaultMessage: 'User',
    description: 'Background job initiator label for an authenticated user.',
  },
  'operations.job.initiator.anonymous': {
    defaultMessage: 'Anonymous user',
    description: 'Background job initiator label for an unauthenticated user.',
  },
  'operations.job.initiator.system': {
    defaultMessage: 'System',
    description: 'Background job initiator label for an internal system action.',
  },
  'operations.job.initiator.access.public': {
    defaultMessage: 'Public',
    description: 'Background job initiator access label for public access.',
  },
  'operations.job.initiator.access.user': {
    defaultMessage: 'User',
    description: 'Background job initiator access label for authenticated-user access.',
  },
  'operations.job.initiator.access.admin': {
    defaultMessage: 'Administrator',
    description: 'Background job initiator access label for administrator access.',
  },
  'operations.job.initiator.unknown': {
    defaultMessage: 'Unknown ({value})',
    description: 'Diagnostic fallback for an unrecognized background job initiator or access value. Value is the raw backend enum value.',
  },
  'operations.job.list.empty': {
    defaultMessage: 'No jobs yet.',
    description: 'Empty-state text for the background jobs table.',
  },
  'operations.job.list.handler': {
    defaultMessage: 'Handler',
    description: 'Background jobs table column for handler name and version.',
  },
  'operations.job.list.status': {
    defaultMessage: 'Status',
    description: 'Background jobs table column for job status.',
  },
  'operations.job.list.attempts': {
    defaultMessage: 'Attempts',
    description: 'Background jobs table column for attempts used and allowed.',
  },
  'operations.job.list.cronSource': {
    defaultMessage: 'Cron / Source',
    description: 'Background jobs table column for cron schedule or other source.',
  },
  'operations.job.list.sourceRun': {
    defaultMessage: 'Run {id}',
    description: 'Compact source run label. Id is a shortened run ID.',
  },
  'operations.job.list.timeline': {
    defaultMessage: 'Timeline',
    description: 'Background jobs table column for job timestamps.',
  },
  'operations.job.list.timelineScheduled': {
    defaultMessage: 'Scheduled {time}',
    description: 'Background job timeline entry for scheduled time.',
  },
  'operations.job.list.timelineCreated': {
    defaultMessage: 'Created {time}',
    description: 'Background job timeline entry for creation time.',
  },
  'operations.job.list.timelineUpdated': {
    defaultMessage: 'Updated {time}',
    description: 'Background job timeline entry for update time.',
  },
  'operations.job.list.lastError': {
    defaultMessage: 'Last Error',
    description: 'Background jobs table column for the most recent backend error.',
  },
  'operations.job.status.cancelling': {
    defaultMessage: 'Cancelling',
    description: 'Background job status label after cancellation is requested.',
  },
  'operations.job.status.queued': {
    defaultMessage: 'queued',
    description: 'Background job status label for a queued job.',
  },
  'operations.job.status.running': {
    defaultMessage: 'running',
    description: 'Background job or attempt status label while running.',
  },
  'operations.job.status.succeeded': {
    defaultMessage: 'succeeded',
    description: 'Background job or attempt status label after success.',
  },
  'operations.job.status.failed': {
    defaultMessage: 'failed',
    description: 'Background job or attempt status label after failure.',
  },
  'operations.job.status.cancelled': {
    defaultMessage: 'cancelled',
    description: 'Background job status label after cancellation.',
  },
  'operations.job.status.leased': {
    defaultMessage: 'leased',
    description: 'Background job attempt status label while leased to a worker.',
  },
  'operations.job.status.retryable': {
    defaultMessage: 'retryable',
    description: 'Background job attempt status label when another attempt can be made.',
  },
  'operations.job.status.interrupted': {
    defaultMessage: 'interrupted',
    description: 'Background job attempt status label after interruption.',
  },
  'operations.run.title': {
    defaultMessage: '{agent} · Run {id}',
    description: 'Run detail page title. Agent is an agent name and id is a shortened run ID.',
  },
  'operations.run.notFound': {
    defaultMessage: 'Run not found',
    description: 'Toast title when a requested run does not exist.',
  },
  'operations.run.conversation': {
    defaultMessage: 'Conversation',
    description: 'Heading above messages associated with a run.',
  },
  'operations.run.platformError': {
    defaultMessage: "Platform error - provider, network, or auth failure upstream of the app. Retrying may help; fixing the app code won't.",
    description: 'Guidance shown when a run failed outside the app.',
  },
  'operations.run.actions': {
    defaultMessage: 'Actions',
    description: 'Heading above actions performed during a run.',
  },
  'operations.run.actionFallback': {
    defaultMessage: 'action',
    description: 'Fallback action type label when a run action has no type.',
  },
  'operations.run.fix.button': {
    defaultMessage: 'Fix this error',
    description: 'Button label that starts an app fix based on a failed run.',
  },
  'operations.run.fix.readOnly': {
    defaultMessage: 'Push the fix to the connected Git repository, then rebuild the app.',
    description: 'Guidance for fixing a run error when the Git repository is read-only.',
  },
  'operations.run.fix.dialogTitle': {
    defaultMessage: 'Fix App Error',
    description: 'Dialog title for starting an app fix from a failed run.',
  },
  'operations.run.fix.contextNotice': {
    defaultMessage: 'The full run context (messages, actions, errors) will be passed to the app builder.',
    description: 'Notice explaining what context is sent when starting an app fix.',
  },
  'operations.run.fix.instructionsPlaceholder': {
    defaultMessage: 'Additional instructions (optional)',
    description: 'Placeholder for optional app-fix instructions.',
  },
  'operations.run.fix.start': {
    defaultMessage: 'Start Fix',
    description: 'Button label that starts an app fix.',
  },
  'operations.run.fix.started': {
    defaultMessage: 'Fix started',
    description: 'Toast title after an app fix starts.',
  },
  'operations.run.fix.failed': {
    defaultMessage: 'Fix failed',
    description: 'Toast title when an app fix cannot be started.',
  },
  'operations.run.logs': {
    defaultMessage: 'Logs',
    description: 'Heading above run standard-output logs.',
  },
  'operations.run.meter.input': {
    defaultMessage: 'Input',
    description: 'Run token meter label for non-cached input tokens.',
  },
  'operations.run.meter.cached': {
    defaultMessage: 'Cached',
    description: 'Run token meter label for cached input tokens.',
  },
  'operations.run.meter.output': {
    defaultMessage: 'Output',
    description: 'Run token meter label for output tokens.',
  },
  'operations.run.list.empty': {
    defaultMessage: 'No runs yet.',
    description: 'Empty-state text for the runs table.',
  },
  'operations.run.list.status': {
    defaultMessage: 'Status',
    description: 'Runs table column for run status.',
  },
  'operations.run.list.trigger': {
    defaultMessage: 'Trigger',
    description: 'Runs table column for what triggered a run.',
  },
  'operations.run.list.started': {
    defaultMessage: 'Started',
    description: 'Runs table column for run start time.',
  },
  'operations.run.list.duration': {
    defaultMessage: 'Duration',
    description: 'Runs table column for run duration.',
  },
  'operations.run.list.cost': {
    defaultMessage: 'Cost',
    description: 'Runs table column for estimated LLM cost.',
  },
  'operations.run.list.version': {
    defaultMessage: 'Version',
    description: 'Runs table column for the app source revision.',
  },
  'operations.run.status.done': {
    defaultMessage: 'done',
    description: 'Run status label for a finished run.',
  },
  'operations.run.status.success': {
    defaultMessage: 'success',
    description: 'Run status label for a successful run.',
  },
  'operations.run.status.completed': {
    defaultMessage: 'completed',
    description: 'Run status label for a completed run.',
  },
  'operations.run.status.running': {
    defaultMessage: 'running',
    description: 'Run status label while a run is in progress.',
  },
  'operations.run.status.toolErrors': {
    defaultMessage: 'tool_errors',
    description: 'Run status label when one or more tool calls failed.',
  },
  'operations.run.status.timeout': {
    defaultMessage: 'timeout',
    description: 'Run status label after a timeout.',
  },
  'operations.run.status.error': {
    defaultMessage: 'error',
    description: 'Run status label after an error.',
  },
  'operations.run.status.failed': {
    defaultMessage: 'failed',
    description: 'Run status label after failure.',
  },
  'operations.run.status.suspended': {
    defaultMessage: 'suspended',
    description: 'Run status label while a run is suspended.',
  },
  'operations.run.status.cancelled': {
    defaultMessage: 'cancelled',
    description: 'Run status label after cancellation.',
  },
  'operations.run.trigger.prompt': {
    defaultMessage: 'prompt',
    description: 'Run trigger label for a web-chat prompt.',
  },
  'operations.run.trigger.bridge': {
    defaultMessage: 'bridge',
    description: 'Run trigger label for a chat bridge.',
  },
  'operations.run.trigger.code': {
    defaultMessage: 'code',
    description: 'Run trigger label for an app HTTP route.',
  },
  'operations.run.trigger.webhook': {
    defaultMessage: 'webhook',
    description: 'Run trigger label for a webhook.',
  },
  'operations.run.trigger.cron': {
    defaultMessage: 'cron',
    description: 'Run trigger label for a cron schedule.',
  },
  'operations.run.trigger.a2a': {
    defaultMessage: 'a2a',
    description: 'Run trigger label for an agent-to-agent request.',
  },
  'operations.run.trigger.job': {
    defaultMessage: 'job',
    description: 'Run trigger label for a background job attempt.',
  },
  'operations.run.trigger.background': {
    defaultMessage: 'background',
    description: 'Run trigger label for a background invocation.',
  },
  'operations.run.trigger.route': {
    defaultMessage: 'route',
    description: 'Run trigger label for an HTTP route.',
  },
  'operations.duration.lessThanMillisecond': {
    defaultMessage: '<1ms',
    description: 'Duration shorter than one millisecond.',
  },
  'operations.duration.milliseconds': {
    defaultMessage: '{value}ms',
    description: 'Duration in milliseconds.',
  },
  'operations.duration.seconds': {
    defaultMessage: '{value}s',
    description: 'Duration in seconds.',
  },
  'operations.duration.minutesSeconds': {
    defaultMessage: '{minutes}m {seconds}s',
    description: 'Duration in minutes and seconds.',
  },
  'operations.duration.hoursMinutes': {
    defaultMessage: '{hours}h {minutes}m',
    description: 'Duration in hours and minutes.',
  },
  'operations.schedule.empty': {
    defaultMessage: 'No schedules registered.',
    description: 'Empty-state text for the schedules table.',
  },
  'operations.schedule.slug': {
    defaultMessage: 'Slug',
    description: 'Schedules table column for the schedule slug.',
  },
  'operations.schedule.description': {
    defaultMessage: 'Description',
    description: 'Schedules table column for the externally supplied schedule description.',
  },
  'operations.schedule.job': {
    defaultMessage: 'Job',
    description: 'Schedules table column for the background job handler.',
  },
  'operations.schedule.schedule': {
    defaultMessage: 'Schedule',
    description: 'Schedules table column for the cron expression.',
  },
  'operations.schedule.nextFire': {
    defaultMessage: 'Next Fire',
    description: 'Schedules table column for the next scheduled fire time.',
  },
  'operations.schedule.lastFired': {
    defaultMessage: 'Last Fired',
    description: 'Schedules table column for the most recent fire time.',
  },
  'operations.schedule.fireNow': {
    defaultMessage: 'Fire Now',
    description: 'Schedules table action and column heading for firing a schedule immediately.',
  },
  'operations.schedule.jobQueued': {
    defaultMessage: 'Job queued',
    description: 'Toast title after firing a schedule queues a job.',
  },
  'operations.schedule.jobQueuedDetail': {
    defaultMessage: 'Cron "{slug}" created a background job.',
    description: 'Toast detail after a cron schedule creates a background job. Slug identifies the schedule.',
  },
  'operations.schedule.fireFailed': {
    defaultMessage: 'Failed to fire schedule "{slug}".',
    description: 'Toast detail when a schedule cannot be fired. Slug identifies the schedule.',
  },
})
