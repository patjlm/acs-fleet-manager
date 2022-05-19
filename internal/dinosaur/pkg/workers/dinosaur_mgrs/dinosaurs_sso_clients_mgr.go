package dinosaur_mgrs

import (
	"github.com/golang/glog"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stackrox/acs-fleet-manager/internal/dinosaur/pkg/config"
	"github.com/stackrox/acs-fleet-manager/internal/dinosaur/pkg/services"
	"github.com/stackrox/acs-fleet-manager/pkg/workers"
)

type DinosaurRoutesSsoClientManager struct {
	workers.BaseWorker
	dinosaurService services.DinosaurService
	dinosaurConfig  *config.DinosaurConfig
	vaultService    services.VaultService
}

var _ workers.Worker = &DinosaurRoutesSsoClientManager{}

func NewDinosaurSsoClientManager(dinosaurService services.DinosaurService, vaultService services.VaultService, kafkfConfig *config.DinosaurConfig) *DinosaurRoutesSsoClientManager {
	return &DinosaurRoutesSsoClientManager{
		BaseWorker: workers.BaseWorker{
			Id:         uuid.New().String(),
			WorkerType: "dinosaur_sso_client",
			Reconciler: workers.Reconciler{},
		},
		dinosaurService: dinosaurService,
		dinosaurConfig:  kafkfConfig,
		vaultService:    vaultService,
	}
}

func (k *DinosaurRoutesSsoClientManager) Start() {
	k.StartWorker(k)
}

func (k *DinosaurRoutesSsoClientManager) Stop() {
	k.StopWorker(k)
}

func (k *DinosaurRoutesSsoClientManager) Reconcile() []error {
	glog.Infoln("reconciling SSO clients for dinosaurs")
	var errs []error

	dinosaurs, listErr := k.dinosaurService.ListDinosaursWithoutSsoClients()
	if listErr != nil {
		errs = append(errs, errors.Wrap(listErr, "failed to list dinosaurs whose SSO clients are not created"))
	} else {
		glog.Infof("dinosaurs need SSO clients created count = %d", len(dinosaurs))
	}

	for _, dinosaur := range dinosaurs {
		if dinosaur.ClientId == "" {
			glog.Infof("creating SSO client for dinosaur %s", dinosaur.ID)

			clientId, clientSecret, serviceErr := k.dinosaurService.CreateSsoClient(dinosaur)

			if serviceErr != nil {
				errs = append(errs, serviceErr.AsError())
				continue
			}
			// Update with secret going to clientSecretRef
			dinosaur.ClientId = clientId
			clientSecretRef := clientId + "-secret-ref"
			err := k.vaultService.SetSecretString(clientSecretRef, clientSecret, "")
			if err != nil {
				errs = append(errs, err)
				continue
			}
			dinosaur.ClientSecretRef = clientSecretRef
		}

		if err := k.dinosaurService.Update(dinosaur); err != nil {
			errs = append(errs, err)
			continue
		}
	}

	return errs
}
