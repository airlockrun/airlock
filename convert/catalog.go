package convert

import (
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	catalogsvc "github.com/airlockrun/airlock/service/catalog"
)

// CatalogProviderToProto maps the catalog service Provider DTO to
// the wire ProviderInfo.
func CatalogProviderToProto(p catalogsvc.Provider) *airlockv1.ProviderInfo {
	return &airlockv1.ProviderInfo{Id: p.ID, Name: p.Name}
}

// CatalogModelToProto maps the catalog service Model DTO to the wire
// ModelInfo.
func CatalogModelToProto(m catalogsvc.Model) *airlockv1.ModelInfo {
	return &airlockv1.ModelInfo{
		Id:           m.ID,
		Name:         m.Name,
		ProviderId:   m.ProviderID,
		Kind:         m.Kind,
		ToolCall:     m.ToolCall,
		Reasoning:    m.Reasoning,
		Caps:         m.Caps,
		CostInput:    m.CostInput,
		CostOutput:   m.CostOutput,
		ContextLimit: m.ContextLimit,
		OutputLimit:  m.OutputLimit,
	}
}

// ProviderCapabilityToProto maps the catalog service capability DTO
// to the wire ProviderCapabilityInfo.
func ProviderCapabilityToProto(c catalogsvc.ProviderCapability) *airlockv1.ProviderCapabilityInfo {
	return &airlockv1.ProviderCapabilityInfo{
		ProviderId:   c.ProviderID,
		DisplayName:  c.DisplayName,
		Capabilities: c.Capabilities,
		Configured:   c.Configured,
		CatalogOnly:  c.CatalogOnly,
	}
}
