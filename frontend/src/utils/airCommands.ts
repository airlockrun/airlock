export function airlockInstallCommand(launcherImport: string, version: string): string {
  return `go install ${launcherImport}@v${version.replace(/^v/, '')}`
}

export function airlockInitCommand(dir: string, airlockURL: string): string {
  return `airlock init ${dir} --url ${airlockURL}`
}

export function airlockCloneCommand(agent: string, dir: string, airlockURL: string): string {
  return `airlock clone ${agent} --url ${airlockURL} ${dir}`
}
