package service

import (
	"context"
)

var defaultFilmFieldClassifications = map[string]Classification{
	"title":        ClassificationPublic,
	"time_elapsed": ClassificationSensitive,
}

func BuildFilmReadResource(ctx context.Context, reader ClassificationMetadataReader, record FilmRecord) (Resource, error) {
	fields, err := buildFilmFields(ctx, reader)
	if err != nil {
		return Resource{}, err
	}
	return Resource{
		Type:     "film",
		ID:       record.ID,
		TenantID: record.TenantID,
		Fields:   fields,
	}, nil
}

func BuildFilmWriteResource(ctx context.Context, reader ClassificationMetadataReader, tenantID, filmID string) (Resource, error) {
	fields, err := buildFilmFields(ctx, reader)
	if err != nil {
		return Resource{}, err
	}
	return Resource{
		Type:     "film",
		ID:       filmID,
		TenantID: tenantID,
		Fields:   fields,
	}, nil
}

func buildFilmFields(ctx context.Context, reader ClassificationMetadataReader) (map[string]FieldMeta, error) {
	fields := make(map[string]FieldMeta, len(defaultFilmFieldClassifications))
	for fieldName, classification := range defaultFilmFieldClassifications {
		fields[fieldName] = FieldMeta{Classification: classification}
	}

	if reader == nil {
		return fields, nil
	}

	classifications, err := reader.GetByResourceType(ctx, "film")
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
