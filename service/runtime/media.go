package runtime

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"time"

	"github.com/airlockrun/agentsdk/capability"
	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/audio"
	"github.com/airlockrun/airlock/db/dbq"
	agentstorage "github.com/airlockrun/airlock/service/agentstorage"
	"github.com/airlockrun/airlock/service/execution"
	"github.com/airlockrun/goai/message"
	"github.com/airlockrun/goai/model"
	"github.com/airlockrun/goai/stream"
	"github.com/airlockrun/goai/tool"
	solprovider "github.com/airlockrun/sol/provider"
	"github.com/google/uuid"
)

func (h *Service) RuntimeMedia(ctx context.Context, scope wire.RuntimeContext, operation string, input json.RawMessage) (result tool.Result, err error) {
	scope, err = h.admittedContext(ctx, scope)
	if err != nil {
		return result, err
	}
	agentID, err := uuid.Parse(scope.AgentID)
	if err != nil {
		return result, err
	}
	runID, err := uuid.Parse(scope.RunID)
	if err != nil {
		return result, err
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := execution.Watch(ctx, dbq.New(h.db.Pool()), agentID, runID, cancel)
	defer func() { cancel(); stop() }()
	encode := func(value any) (tool.Result, error) {
		data, err := json.Marshal(value)
		return tool.Result{Output: string(data)}, err
	}
	if operation == "analyze_image" {
		var req capability.AnalyzeImageInput
		if err := json.Unmarshal(input, &req); err != nil {
			return result, err
		}
		file, err := h.files.ResolveForRuntime(ctx, scope, req.Path, agentstorage.OperationRead)
		if err != nil {
			return result, err
		}
		m, err := h.RuntimeModel(ctx, agentID, runID, "", "vision")
		if err != nil {
			return result, err
		}
		if req.Question == "" {
			req.Question = "Describe this image."
		}
		_, mimeType, err := h.s3.HeadObject(ctx, file.S3Key)
		if err != nil {
			return result, err
		}
		events, err := m.Stream(ctx, &stream.CallOptions{Messages: []message.Message{message.NewUserMessageWithParts(message.TextPart{Text: req.Question}, message.FilePart{Data: message.FileDataBytes{Data: "s3ref:" + file.Relative}, MimeType: mimeType})}})
		if err != nil {
			return result, err
		}
		for event := range events {
			if delta, ok := event.Data.(stream.TextDeltaEvent); ok {
				result.Output += delta.Text
			}
			if failure, ok := event.Data.(stream.ErrorEvent); ok {
				err = failure.Error
			}
		}
		return result, err
	}
	capabilityName := map[string]string{"transcribe_audio": "transcription", "generate_image": "image", "speak": "speech", "embed": "embedding"}[operation]
	resolved, err := h.ResolveModel(ctx, agentID.String(), "", capabilityName)
	if err != nil {
		return result, err
	}
	capture := LlmUsageCapture{ProviderCatalogID: resolved.ProviderID, ProviderSlug: resolved.ProviderSlug, Model: resolved.ModelID, Capability: capabilityName}
	if scope.Definition != nil {
		admitted, err := execution.Resolve(ctx, dbq.New(h.db.Pool()), agentID, runID)
		if err != nil {
			return result, err
		}
		capture.TaskOwnerToken = uuid.UUID(admitted.Run.RuntimeOwnerToken.Bytes)
		capture.TaskUsageID = uuid.New()
	}
	options := h.LanguageModelOptions(resolved)
	started := time.Now()
	defer func() {
		capture.Latency, capture.Errored = time.Since(started), err != nil
		if accountingErr := h.RecordLLMUsage(agentID, runID.String(), capture); accountingErr != nil {
			result, err = tool.Result{}, errors.Join(err, accountingErr)
		}
	}()
	var data []byte
	var mimeType, saveAs string
	switch operation {
	case "embed":
		var req capability.EmbedInput
		if err := json.Unmarshal(input, &req); err != nil {
			return result, err
		}
		if req.Text != "" && len(req.Texts) != 0 {
			return result, errors.New("text and texts are mutually exclusive")
		}
		if req.Text != "" {
			req.Texts = []string{req.Text}
		}
		if len(req.Texts) == 0 {
			return result, errors.New("embedding text is required")
		}
		m := solprovider.CreateEmbeddingModel(resolved.ProviderID, resolved.ModelID, options)
		if m == nil {
			return result, errors.New("provider does not support embeddings")
		}
		response, err := m.Embed(ctx, model.EmbedCallOptions{Values: req.Texts})
		if err != nil {
			return result, err
		}
		capture.TokensIn = int64(response.Usage.Tokens)
		vectors := make([][]float64, len(response.Embeddings))
		for i, embedding := range response.Embeddings {
			vectors[i] = embedding.Values
		}
		if req.Text != "" && len(vectors) == 1 {
			return encode(vectors[0])
		}
		return encode(vectors)
	case "transcribe_audio":
		var req capability.TranscribeAudioInput
		if err := json.Unmarshal(input, &req); err != nil {
			return result, err
		}
		file, err := h.files.ResolveForRuntime(ctx, scope, req.Path, agentstorage.OperationRead)
		if err != nil {
			return result, err
		}
		_, mimeType, err := h.s3.HeadObject(ctx, file.S3Key)
		if err != nil {
			return result, err
		}
		reader, err := h.s3.GetObject(ctx, file.S3Key)
		if err != nil {
			return result, err
		}
		defer reader.Close()
		data, err := io.ReadAll(io.LimitReader(reader, 25<<20+1))
		if err != nil {
			return result, err
		}
		if len(data) > 25<<20 {
			return result, errors.New("audio exceeds 25 MiB")
		}
		filename := filepath.Base(file.Relative)
		if normalized, name, mime, err := audio.NormalizeForSTT(ctx, data, filename, mimeType); err == nil {
			data, filename, mimeType = normalized, name, mime
		}
		m := solprovider.CreateTranscriptionModel(resolved.ProviderID, resolved.ModelID, options)
		if m == nil {
			return result, errors.New("provider does not support transcription")
		}
		response, err := m.Transcribe(ctx, model.TranscribeCallOptions{Audio: data, MimeType: mimeType, Filename: filename, Language: req.Language, Prompt: req.Prompt})
		if err != nil {
			return result, err
		}
		capture.UnitKind = "second"
		if response.Usage != nil {
			capture.Units = response.Usage.DurationSeconds
		}
		return encode(map[string]string{"text": response.Text})
	case "generate_image":
		var req capability.GenerateImageInput
		if err := json.Unmarshal(input, &req); err != nil {
			return result, err
		}
		m := solprovider.CreateImageModel(resolved.ProviderID, resolved.ModelID, options)
		if m == nil {
			return result, errors.New("provider does not support image generation")
		}
		response, err := m.Generate(ctx, model.ImageCallOptions{Prompt: req.Prompt, N: 1, Size: req.Size, AspectRatio: req.AspectRatio, Seed: req.Seed})
		if err != nil {
			return result, err
		}
		capture.UnitKind, capture.Units = "image", float64(len(response.Images))
		if len(response.Images) != 1 {
			return result, errors.New("image provider returned no single image")
		}
		image := response.Images[0]
		mimeType, saveAs = image.MimeType, req.SaveAs
		if image.Base64 != "" {
			data, err = base64.StdEncoding.DecodeString(image.Base64)
		} else {
			request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, image.URL, nil)
			if requestErr != nil {
				return result, requestErr
			}
			response, fetchErr := h.httpNetwork.Client(time.Minute).Do(request)
			if fetchErr != nil {
				return result, fetchErr
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				return result, fmt.Errorf("generated image HTTP %d", response.StatusCode)
			}
			data, err = io.ReadAll(io.LimitReader(response.Body, 25<<20+1))
		}
	case "speak":
		var req capability.SpeakInput
		if err := json.Unmarshal(input, &req); err != nil {
			return result, err
		}
		m := solprovider.CreateSpeechModel(resolved.ProviderID, resolved.ModelID, options)
		if m == nil {
			return result, errors.New("provider does not support speech")
		}
		response, err := m.Generate(ctx, model.SpeechCallOptions{Text: req.Text, Voice: req.Voice, OutputFormat: req.OutputFormat, Speed: req.Speed})
		if err != nil {
			return result, err
		}
		capture.UnitKind = "character"
		if response.Usage != nil {
			capture.Units = float64(response.Usage.Characters)
		}
		data, mimeType, saveAs = response.Audio, response.MimeType, req.SaveAs
		if response.AudioReader != nil {
			data, err = io.ReadAll(io.LimitReader(response.AudioReader, 25<<20+1))
		}
	}
	if err != nil {
		return result, err
	}
	if len(data) == 0 || len(data) > 25<<20 {
		return result, errors.New("generated media has invalid size")
	}
	if mimeType == "" {
		mimeType = http.DetectContentType(data)
	}
	if saveAs == "" {
		saveAs = "tmp/media/" + uuid.NewString()
	}
	file, err := h.files.ResolveForRuntime(ctx, scope, saveAs, agentstorage.OperationWrite)
	if err != nil {
		return result, err
	}
	if err := h.s3.PutObjectStream(ctx, file.S3Key, bytes.NewReader(data), int64(len(data)), mimeType); err != nil {
		return result, err
	}
	return encode(map[string]any{"file": file.Relative, "mimeType": mimeType, "size": len(data)})
}
