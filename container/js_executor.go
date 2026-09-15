package container

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/airlockrun/airlock/config"
	"github.com/airlockrun/airlock/db/dbq"
	cerrdefs "github.com/containerd/errdefs"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/moby/moby/api/pkg/stdcopy"
	dcontainer "github.com/moby/moby/api/types/container"
	dockerclient "github.com/moby/moby/client"
)

// JSExecutorManager is intentionally separate from reusable app containers.
// The stream is non-TTY stdin/stdout; Close must unblock both directions and
// destroy the realm. No endpoint, credentials, workspace, or network is exposed.
type JSExecutorManager interface {
	StartJSExecutor(context.Context, uuid.UUID, uuid.UUID) (io.ReadWriteCloser, error)
}

const jsExecutorResource = "js-executor"
const jsRunLabel = "run.airlock.run"
const jsOwnerLabel = "run.airlock.owner-token"

func jsExecutorConfig(image, instance string, runID, token uuid.UUID) (*dcontainer.Config, *dcontainer.HostConfig) {
	pids := int64(64)
	return &dcontainer.Config{
			Image: image, User: "65532:65532", OpenStdin: true, AttachStdin: true, AttachStdout: true, AttachStderr: true,
			Labels: map[string]string{config.LabelInstance: instance, labelResource: jsExecutorResource, jsRunLabel: runID.String(), jsOwnerLabel: token.String()},
		}, &dcontainer.HostConfig{
			NetworkMode: "none", ReadonlyRootfs: true, CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"},
			Resources: dcontainer.Resources{Memory: 256 << 20, MemorySwap: 256 << 20, NanoCPUs: 1_000_000_000, PidsLimit: &pids},
			Tmpfs:     map[string]string{"/tmp": "rw,noexec,nosuid,nodev,size=64m,mode=1777"},
			LogConfig: dcontainer.LogConfig{Type: "none"},
		}
}

func (m *DockerManager) StartJSExecutor(ctx context.Context, runID, token uuid.UUID) (io.ReadWriteCloser, error) {
	if runID == uuid.Nil || token == uuid.Nil || m.cfg.JSExecutorImage == "" {
		return nil, errors.New("JS executor requires image, run and owner token")
	}
	tx, err := m.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if _, err := q.LockConversationRunLease(ctx, dbq.LockConversationRunLeaseParams{RunID: pgtype.UUID{Bytes: runID, Valid: true}, OwnerToken: pgtype.UUID{Bytes: token, Valid: true}}); err != nil {
		return nil, fmt.Errorf("JS executor lease: %w", err)
	}
	cfg, host := jsExecutorConfig(m.cfg.JSExecutorImage, m.cfg.InstanceID, runID, token)
	name := m.cfg.InstanceID + "-js-" + runID.String() + "-" + token.String()
	created, err := m.client.ContainerCreate(ctx, dockerclient.ContainerCreateOptions{Config: cfg, HostConfig: host, Name: name})
	if err != nil {
		return nil, err
	}
	remove := func() error {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := m.client.ContainerRemove(cleanup, created.ID, dockerclient.ContainerRemoveOptions{Force: true})
		if cerrdefs.IsNotFound(err) {
			return nil
		}
		return err
	}
	attach, err := m.client.ContainerAttach(ctx, created.ID, dockerclient.ContainerAttachOptions{Stream: true, Stdin: true, Stdout: true, Stderr: true})
	if err != nil {
		return nil, errors.Join(err, remove())
	}
	if _, err := m.client.ContainerStart(ctx, created.ID, dockerclient.ContainerStartOptions{}); err != nil {
		attach.Close()
		return nil, errors.Join(err, remove())
	}
	if err := tx.Commit(ctx); err != nil {
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

type jsAttach struct {
	attach dockerclient.ContainerAttachResult
	reader *io.PipeReader
	remove func() error
	once   sync.Once
	err    error
}

func (s *jsAttach) Read(p []byte) (int, error)  { return s.reader.Read(p) }
func (s *jsAttach) Write(p []byte) (int, error) { return s.attach.Conn.Write(p) }
func (s *jsAttach) Close() error {
	s.once.Do(func() {
		s.attach.Close()
		_ = s.reader.Close()
		s.err = s.remove()
	})
	return s.err
}

// ReapJSExecutors only removes this instance's containers whose exact owner
// lease is no longer live. Another replica's live execution is never reclaimed.
func (m *DockerManager) ReapJSExecutors(ctx context.Context) error {
	list, err := m.client.ContainerList(ctx, dockerclient.ContainerListOptions{All: true, Filters: make(dockerclient.Filters).Add(
		"label", config.LabelInstance+"="+m.cfg.InstanceID, labelResource+"="+jsExecutorResource,
	)})
	if err != nil {
		return err
	}
	q := dbq.New(m.pool)
	for _, item := range list.Items {
		runID, err := uuid.Parse(item.Labels[jsRunLabel])
		if err != nil {
			return err
		}
		token, err := uuid.Parse(item.Labels[jsOwnerLabel])
		if err != nil {
			return err
		}
		live, err := q.IsRuntimeLeaseLive(ctx, dbq.IsRuntimeLeaseLiveParams{RunID: pgtype.UUID{Bytes: runID, Valid: true}, OwnerToken: pgtype.UUID{Bytes: token, Valid: true}})
		if err != nil {
			return err
		}
		if live {
			continue
		}
		if _, err := m.client.ContainerRemove(ctx, item.ID, dockerclient.ContainerRemoveOptions{Force: true}); err != nil && !cerrdefs.IsNotFound(err) {
			return err
		}
	}
	return nil
}
