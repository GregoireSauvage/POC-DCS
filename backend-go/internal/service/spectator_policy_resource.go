package service

import (
	"context"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
)

var defaultSpectatorFieldClassifications = map[string]Classification{
	"name":        ClassificationPII,
	"age":         ClassificationSensitive,
	"external_id": ClassificationPII,
}

func BuildSpectatorReadResource(ctx context.Context, reader ClassificationMetadataReader, spectator *domain.Spectator) (Resource, error) {
	fields, err := buildSpectatorFields(ctx, reader)
	if err != nil {
		return Resource{}, err
	}
	if spectator == nil {
		return Resource{Type: "spectator", Fields: fields}, nil
	}
	return Resource{
		Type:     "spectator",
		ID:       spectator.ID,
		TenantID: spectator.TenantID,
		Labels:   append([]string(nil), spectator.Labels...),
		Fields:   fields,
	}, nil
}

func BuildSpectatorWriteResource(ctx context.Context, reader ClassificationMetadataReader, tenantID, spectatorID, ownerUserID string, labels []string) (Resource, error) {
	fields, err := buildSpectatorFields(ctx, reader)
	if err != nil {
		return Resource{}, err
	}
	return Resource{
		Type:     "spectator",
		ID:       spectatorID,
		TenantID: tenantID,
		OwnerID:  ownerUserID,
		Labels:   append([]string(nil), labels...),
		Fields:   fields,
	}, nil
}

func BuildSpectatorSearchResource(ctx context.Context, reader ClassificationMetadataReader, tenantID string) (Resource, error) {
	fields, err := buildSpectatorFields(ctx, reader)
	if err != nil {
		return Resource{}, err
	}
	return Resource{
		Type:     "spectator",
		TenantID: tenantID,
		Fields:   fields,
	}, nil
}

func buildSpectatorFields(ctx context.Context, reader ClassificationMetadataReader) (map[string]FieldMeta, error) {
	fields := make(map[string]FieldMeta, len(defaultSpectatorFieldClassifications))
	for fieldName, classification := range defaultSpectatorFieldClassifications {
		fields[fieldName] = FieldMeta{Classification: classification}
	}

	if reader == nil {
		return fields, nil
	}

	classifications, err := reader.GetByResourceType(ctx, "spectator")
	if err != nil {
		return nil, err
	}
	for _, classification := range classifications {
		if classification == nil {
			continue
		}
		fields[classification.FieldName] = FieldMeta{
			Classification: Classification(classification.Classification),
		}
	}

	return fields, nil
}
