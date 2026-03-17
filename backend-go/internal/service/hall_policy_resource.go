package service

import "context"

var defaultHallFieldClassifications = map[string]Classification{
	"name":            ClassificationPublic,
	"owner_user_id":   ClassificationInternal,
	"current_film_id": ClassificationInternal,
}

func BuildHallReadResource(ctx context.Context, reader ClassificationMetadataReader, record HallRecord) (Resource, error) {
	fields, err := buildHallFields(ctx, reader)
	if err != nil {
		return Resource{}, err
	}
	return Resource{
		Type:     "hall",
		ID:       record.ID,
		TenantID: record.TenantID,
		OwnerID:  record.OwnerUserID,
		Fields:   fields,
	}, nil
}

func BuildHallWriteResource(ctx context.Context, reader ClassificationMetadataReader, tenantID, hallID, ownerUserID string, labels []string) (Resource, error) {
	fields, err := buildHallFields(ctx, reader)
	if err != nil {
		return Resource{}, err
	}
	return Resource{
		Type:     "hall",
		ID:       hallID,
		TenantID: tenantID,
		OwnerID:  ownerUserID,
		Labels:   append([]string(nil), labels...),
		Fields:   fields,
	}, nil
}

func buildHallFields(ctx context.Context, reader ClassificationMetadataReader) (map[string]FieldMeta, error) {
	fields := make(map[string]FieldMeta, len(defaultHallFieldClassifications))
	for fieldName, classification := range defaultHallFieldClassifications {
		fields[fieldName] = FieldMeta{Classification: classification}
	}

	if reader == nil {
		return fields, nil
	}

	classifications, err := reader.GetByResourceType(ctx, "hall")
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
