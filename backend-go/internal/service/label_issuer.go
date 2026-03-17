package service

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/neoweyss/poc-dcs/backend-go/internal/domain"
)

type ClassificationMetadataReader interface {
	GetByResourceType(ctx context.Context, resourceType string) ([]*domain.FieldClassification, error)
}

type StaticClassificationMetadataReader struct {
	byResource map[string][]domain.FieldClassification
}

func NewStaticClassificationReader(byResource map[string][]domain.FieldClassification) *StaticClassificationMetadataReader {
	cloned := make(map[string][]domain.FieldClassification, len(byResource))
	for resourceType, classifications := range byResource {
		items := make([]domain.FieldClassification, len(classifications))
		copy(items, classifications)
		cloned[resourceType] = items
	}
	return &StaticClassificationMetadataReader{byResource: cloned}
}

func (r *StaticClassificationMetadataReader) GetByResourceType(_ context.Context, resourceType string) ([]*domain.FieldClassification, error) {
	classifications := r.byResource[resourceType]
	results := make([]*domain.FieldClassification, 0, len(classifications))
	for i := range classifications {
		classification := classifications[i]
		results = append(results, &classification)
	}
	return results, nil
}

type ServerLabelIssuer struct {
	policy   ClassificationPolicy
	reader   ClassificationMetadataReader
	fallback map[string]Classification
}

func NewServerLabelIssuer(
	policy ClassificationPolicy,
	reader ClassificationMetadataReader,
	fallback map[string]Classification,
) *ServerLabelIssuer {
	clonedFallback := make(map[string]Classification, len(fallback))
	for resourceType, classification := range fallback {
		clonedFallback[resourceType] = classification
	}
	return &ServerLabelIssuer{
		policy:   policy,
		reader:   reader,
		fallback: clonedFallback,
	}
}

func (i *ServerLabelIssuer) Issue(ctx context.Context, access AccessContext, resource Resource) (Label, error) {
	classification, err := i.maxClassification(ctx, resource.Type)
	if err != nil {
		return Label{}, err
	}

	categories := append([]string(nil), resource.Labels...)
	sort.Strings(categories)

	originator := access.Principal.TenantID
	if originator == "" {
		originator = resource.TenantID
	}

	now := time.Now().UTC()
	return Label{
		PolicyID:       i.policy.PolicyID(),
		PolicyVersion:  i.policy.PolicyVersion(),
		Classification: classification,
		Categories:     categories,
		Originator:     originator,
		CreatedAt:      now,
		UpdatedAt:      now,
	}, nil
}

func (i *ServerLabelIssuer) maxClassification(ctx context.Context, resourceType string) (Classification, error) {
	if i.reader != nil {
		classifications, err := i.reader.GetByResourceType(ctx, resourceType)
		if err != nil {
			return "", fmt.Errorf("load classifications for %s: %w", resourceType, err)
		}
		if len(classifications) > 0 {
			maxClassification := i.policy.DefaultClassification()
			for _, classification := range classifications {
				value := Classification(classification.Classification)
				if classificationRank(value) > classificationRank(maxClassification) {
					maxClassification = value
				}
			}
			return maxClassification, nil
		}
	}

	if classification, ok := i.fallback[resourceType]; ok {
		return classification, nil
	}

	return i.policy.DefaultClassification(), nil
}

func classificationRank(classification Classification) int {
	switch classification {
	case ClassificationPublic:
		return 0
	case ClassificationInternal:
		return 1
	case ClassificationSensitive:
		return 2
	case ClassificationPII:
		return 3
	default:
		return -1
	}
}

var _ LabelIssuer = (*ServerLabelIssuer)(nil)
