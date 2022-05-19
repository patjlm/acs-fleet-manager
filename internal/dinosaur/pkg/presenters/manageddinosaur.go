package presenters

import (
	"github.com/stackrox/acs-fleet-manager/internal/dinosaur/pkg/api/private"
	v1 "github.com/stackrox/acs-fleet-manager/pkg/api/manageddinosaurs.manageddinosaur.mas/v1"
)

func PresentManagedDinosaur(from *v1.ManagedDinosaur) private.ManagedDinosaur {
	// TODO implement presenter
	res := private.ManagedDinosaur{
		Id:   from.Annotations["mas/id"],
		Kind: from.Kind,
		Metadata: private.ManagedDinosaurAllOfMetadata{
			Name:      from.Name,
			Namespace: from.Namespace,
			Annotations: private.ManagedDinosaurAllOfMetadataAnnotations{
				MasId:          from.Annotations["mas/id"],
				MasPlacementId: from.Annotations["mas/placementId"],
			},
		},
		Spec: private.ManagedDinosaurAllOfSpec{
			Oauth: private.ManagedDinosaurAllOfSpecOauth{
				ClientId:     from.Spec.Oauth.ClientId,
				ClientSecret: from.Spec.Oauth.ClientSecret,
			},
			// TODO implement your spec fields here
		},
	}
	return res
}
