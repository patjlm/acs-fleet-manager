package presenters

import (
	"github.com/stackrox/acs-fleet-manager/internal/dinosaur/internal/api/private"
	v1 "github.com/stackrox/acs-fleet-manager/pkg/api/manageddinosaurs.manageddinosaur.mas/v1"
)

func PresentManagedDinosaur(from *v1.ManagedDinosaur) private.ManagedCentral {
	// TODO implement presenter
	res := private.ManagedCentral{
		Id:   from.Annotations["mas/id"],
		Kind: from.Kind,
		Metadata: private.ManagedCentralAllOfMetadata{
			Name:      from.Name,
			Namespace: from.Namespace,
			Annotations: private.ManagedCentralAllOfMetadataAnnotations{
				MasId:          from.Annotations["mas/id"],
				MasPlacementId: from.Annotations["mas/placementId"],
			},
		},
		Spec: private.ManagedCentralAllOfSpec{
			// TODO implement your spec fields here
		},
	}
	return res
}
