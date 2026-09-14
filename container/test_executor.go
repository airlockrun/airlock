package container

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/airlockrun/airlock/config"
	"github.com/airlockrun/airlock/db/dbq"
	cerrdefs "github.com/containerd/errdefs"
	dcontainer "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// TestJSExecutorManager allocates only build-scoped test realms, using the same
// isolated image and resource recipe as chat execution.
type TestJSExecutorManager interface {
	StartTestJSExecutor(context.Context, uuid.UUID) (io.ReadWriteCloser, error)
}

func (m *DockerManager) StartTestJSExecutor(ctx context.Context, buildID uuid.UUID) (io.ReadWriteCloser, error) {
	if buildID == uuid.Nil || m.cfg.JSExecutorImage == "" {
		return nil, errors.New("test JS executor requires image and build ID")
	}
	build, err := dbq.New(m.pool).GetAgentBuild(ctx, pgtype.UUID{Bytes: buildID, Valid: true})
	if err != nil {
		return nil, err
	}
	active, err := dbq.New(m.pool).AgentBuildIntegrationActive(ctx, dbq.AgentBuildIntegrationActiveParams{ID: build.ID, AgentID: build.AgentID})
	if err != nil {
		return nil, err
	}
	if !active {
		return nil, errors.New("test JS executor build credential is inactive")
	}
	cfg, host := testJSExecutorConfig(m.cfg.JSExecutorImage, m.cfg.InstanceID, buildID)
	created, err := m.client.ContainerCreate(ctx, cfg, host, nil, nil, "")
	if err != nil {
		return nil, err
	}
	remove := func() error {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := m.client.ContainerRemove(cleanup, created.ID, dcontainer.RemoveOptions{Force: true})
		if cerrdefs.IsNotFound(err) {
			return nil
		}
		return err
	}
	attach, err := m.client.ContainerAttach(ctx, created.ID, dcontainer.AttachOptions{Stream: true, Stdin: true, Stdout: true, Stderr: true})
	if err != nil {
		return nil, errors.Join(err, remove())
	}
	if err := m.client.ContainerStart(ctx, created.ID, dcontainer.StartOptions{}); err != nil {
		attach.Close()
		return nil, errors.Join(err, remove())
	}
	reader, writer := io.Pipe()
	stream := &jsAttach{attach: attach, reader: reader, remove: remove}
	go func() {
		_, err := stdcopy.StdCopy(writer, io.Discard, attach.Reader)
		_ = writer.CloseWithError(err)
	}()
	context.AfterFunc(ctx, func() { _ = stream.Close() })
	return stream, nil
}

func testJSExecutorConfig(image, instance string, buildID uuid.UUID) (*dcontainer.Config, *dcontainer.HostConfig) {
	cfg, host := jsExecutorConfig(image, instance, buildID, uuid.New())
	cfg.Labels[labelResource] = "test-js-executor"
	cfg.Labels["run.airlock.build"] = buildID.String()
	delete(cfg.Labels, jsRunLabel)
	delete(cfg.Labels, jsOwnerLabel)
	// Losing the Airlock attachment closes stdin and terminates the supervisor;
	// Docker removes the realm even if the provisioning process exits.
	cfg.StdinOnce = true
	host.AutoRemove = true
	return cfg, host
}

// Reaping takes the same build lock as provisioning. It cannot remove another
// replica's live realm, including one between Docker create and attach.
func (m *DockerManager) reapTestJSExecutors() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	items, err := m.client.ContainerList(ctx, dcontainer.ListOptions{All: true, Filters: filters.NewArgs(
		filters.Arg("label", config.LabelInstance+"="+m.cfg.InstanceID), filters.Arg("label", labelResource+"=test-js-executor"),
	)})
	if err != nil {
		m.logger.Warn("list test executors", zap.Error(err))
		return
	}
	for _, item := range items {
		buildID, err := uuid.Parse(item.Labels["run.airlock.build"])
		if err != nil {
			m.logger.Error("test executor has invalid build label", zap.String("container_id", item.ID))
			continue
		}
		tx, err := m.pool.Begin(ctx)
		if err != nil {
			m.logger.Warn("lock test executor cleanup", zap.Error(err))
			return
		}
		locked, err := dbq.New(tx).TryLockBuildTestExecutor(ctx, buildID.String())
		if err == nil && locked {
			err = m.client.ContainerRemove(ctx, item.ID, dcontainer.RemoveOptions{Force: true})
		}
		_ = tx.Rollback(context.WithoutCancel(ctx))
		if err != nil && !cerrdefs.IsNotFound(err) {
			m.logger.Warn("reap test executor", zap.String("container_id", item.ID), zap.Error(err))
		}
	}
}
