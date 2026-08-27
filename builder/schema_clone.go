package builder

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	postgresClientImage       = "pgvector/pgvector:pg17"
	schemaCloneCleanupTimeout = 30 * time.Second
)

func schemaCloneName(sourceSchema string, buildID uuid.UUID) string {
	return sourceSchema + "_clone_" + hex.EncodeToString(buildID[:8])
}

// cloneSchema streams a consistent PostgreSQL dump of one agent schema into a
// disposable schema owned by the same agent role. pg_dump preserves the full
// schema contract, including constraints, indexes, routines, triggers,
// sequences, and data required to validate a real upgrade.
func (b *BuildService) cloneSchema(ctx context.Context, sourceSchema, cloneName, roleName, password string) (err error) {
	if sourceSchema == "" || cloneName == "" || roleName == "" || password == "" || sourceSchema == cloneName {
		return errors.New("clone schema requires distinct schemas, role, and password")
	}
	cloneIdentifier := pgx.Identifier{cloneName}.Sanitize()
	roleIdentifier := pgx.Identifier{roleName}.Sanitize()
	if _, err := b.db.Pool().Exec(ctx, "CREATE SCHEMA "+cloneIdentifier+" AUTHORIZATION "+roleIdentifier); err != nil {
		return fmt.Errorf("create clone schema: %w", err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, b.dropSchemaCloneWithTimeout(cloneName))
		}
	}()

	clientEnv := append(os.Environ(),
		"PGHOST="+b.cfg.DBHost,
		"PGPORT="+b.cfg.DBPort,
		"PGDATABASE="+b.cfg.DBName,
		"PGUSER="+roleName,
		"PGPASSWORD="+password,
		"PGSSLMODE="+b.cfg.DBSSLMode,
	)
	dump := b.postgresClientCommand(ctx, "pg_dump", clientEnv,
		"--format=plain", "--no-owner", "--no-privileges", "--schema="+sourceSchema)
	restore := b.postgresClientCommand(ctx, "psql", clientEnv,
		"--no-psqlrc", "--set=ON_ERROR_STOP=1", "--single-transaction")
	if err := cloneSchemaWithCommands(dump, restore, sourceSchema, cloneName); err != nil {
		return err
	}
	return nil
}

func (b *BuildService) dropSchemaCloneWithTimeout(cloneName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), schemaCloneCleanupTimeout)
	defer cancel()
	return b.dropSchemaClone(ctx, cloneName)
}

func (b *BuildService) postgresClientCommand(ctx context.Context, program string, env []string, args ...string) *exec.Cmd {
	if path, err := exec.LookPath(program); err == nil {
		cmd := exec.CommandContext(ctx, path, args...)
		cmd.Env = env
		return cmd
	}
	dockerArgs := []string{"run", "--rm", "-i"}
	if b.cfg.DockerNetwork != "" {
		dockerArgs = append(dockerArgs, "--network", b.cfg.DockerNetwork)
	}
	for _, name := range []string{"PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGSSLMODE"} {
		dockerArgs = append(dockerArgs, "-e", name)
	}
	dockerArgs = append(dockerArgs, postgresClientImage, program)
	dockerArgs = append(dockerArgs, args...)
	cmd := exec.CommandContext(ctx, "docker", dockerArgs...)
	cmd.Env = replacePostgresHost(env, b.cfg.DBHostAgent, b.cfg.DBPortAgent)
	return cmd
}

func replacePostgresHost(env []string, host, port string) []string {
	result := make([]string, 0, len(env)+2)
	for _, value := range env {
		if strings.HasPrefix(value, "PGHOST=") || strings.HasPrefix(value, "PGPORT=") {
			continue
		}
		result = append(result, value)
	}
	return append(result, "PGHOST="+host, "PGPORT="+port)
}

func cloneSchemaWithCommands(dump, restore *exec.Cmd, sourceSchema, cloneName string) error {
	dumpOutput, err := dump.StdoutPipe()
	if err != nil {
		return fmt.Errorf("open pg_dump output: %w", err)
	}
	restoreInput, err := restore.StdinPipe()
	if err != nil {
		_ = dumpOutput.Close()
		return fmt.Errorf("open psql input: %w", err)
	}
	var dumpDiagnostic, restoreDiagnostic bytes.Buffer
	dump.Stderr = &dumpDiagnostic
	restore.Stdout = &restoreDiagnostic
	restore.Stderr = &restoreDiagnostic

	if err := restore.Start(); err != nil {
		_ = restoreInput.Close()
		_ = dumpOutput.Close()
		return fmt.Errorf("start psql: %w", err)
	}
	if err := dump.Start(); err != nil {
		_ = dumpOutput.Close()
		_ = restoreInput.Close()
		_ = restore.Process.Kill()
		_ = restore.Wait()
		return fmt.Errorf("start pg_dump: %w", err)
	}

	copyErr := remapSchemaDump(restoreInput, dumpOutput, sourceSchema, cloneName)
	if copyErr != nil {
		_ = dump.Process.Kill()
	}
	dumpErr := dump.Wait()
	closeErr := restoreInput.Close()
	restoreErr := restore.Wait()
	if copyErr != nil {
		return fmt.Errorf("remap schema dump: %w", copyErr)
	}
	if dumpErr != nil {
		return fmt.Errorf("pg_dump failed: %w: %s", dumpErr, strings.TrimSpace(dumpDiagnostic.String()))
	}
	if closeErr != nil {
		return fmt.Errorf("close psql input: %w", closeErr)
	}
	if restoreErr != nil {
		return fmt.Errorf("psql restore failed: %w: %s", restoreErr, strings.TrimSpace(restoreDiagnostic.String()))
	}
	return nil
}

func remapSchemaDump(dst io.Writer, src io.Reader, sourceSchema, cloneName string) error {
	if sourceSchema == "" || cloneName == "" || sourceSchema == cloneName {
		return errors.New("schema remap requires distinct non-empty names")
	}
	reader := bufio.NewReader(src)
	quotedClone := pgx.Identifier{cloneName}.Sanitize()
	inCopy := false
	for {
		line, readErr := reader.ReadString('\n')
		if len(line) > 0 {
			if inCopy {
				if _, err := io.WriteString(dst, line); err != nil {
					return err
				}
				if strings.TrimSpace(line) == `\.` {
					inCopy = false
				}
			} else {
				line = strings.ReplaceAll(line, sourceSchema, cloneName)
				trimmed := strings.TrimSpace(line)
				if trimmed != "CREATE SCHEMA "+cloneName+";" && trimmed != "CREATE SCHEMA "+quotedClone+";" {
					if _, err := io.WriteString(dst, line); err != nil {
						return err
					}
				}
				if strings.HasPrefix(trimmed, "COPY ") && strings.HasSuffix(trimmed, " FROM stdin;") {
					inCopy = true
				}
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				if inCopy {
					return errors.New("unterminated COPY data")
				}
				return nil
			}
			return readErr
		}
	}
}
