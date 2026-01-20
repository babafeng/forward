package ctx

import (
	"context"

	"forward/internal/metadata"
)

type mdKey struct{}

func ContextWithMetadata(ctx context.Context, md metadata.Metadata) context.Context {
	return context.WithValue(ctx, mdKey{}, md)
}

func MetadataFromContext(ctx context.Context) metadata.Metadata {
	v, _ := ctx.Value(mdKey{}).(metadata.Metadata)
	return v
}
