package e2e

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stackrox/acs-fleet-manager/fleetshard/pkg/fleetmanager"
	"github.com/stackrox/acs-fleet-manager/internal/dinosaur/constants"
	"github.com/stackrox/acs-fleet-manager/internal/dinosaur/pkg/api/public"
	"github.com/stackrox/acs-fleet-manager/internal/dinosaur/pkg/services"
	"github.com/stackrox/rox/operator/apis/platform/v1alpha1"
	v1 "k8s.io/api/core/v1"
	apiErrors "k8s.io/apimachinery/pkg/api/errors"
	ctrlClient "sigs.k8s.io/controller-runtime/pkg/client"
)

// TODO(ROX-11468): Why is a central always created as a "eval" instance type?
var (
	centralName = fmt.Sprintf("%s-%d", "e2e-test-central", time.Now().UnixMilli())
)

const (
	defaultPolling = 1 * time.Second
)

// TODO(ROX-11465): Use correct OCM_TOKEN for different clients (console.redhat.com, fleetshard)
var _ = Describe("Central", func() {
	Describe("should be created and deployed to k8s", func() {
		client, err := fleetmanager.NewClient("http://localhost:8000", "cluster-id")
		Expect(err).To(BeNil())

		request := public.CentralRequestPayload{
			Name:          centralName,
			MultiAz:       true,
			CloudProvider: dpCloudProvider,
			Region:        dpRegion,
		}

		var createdCentral *public.CentralRequest
		var namespaceName string
		It("created a central", func() {
			createdCentral, err = client.CreateCentral(request)
			Expect(err).To(BeNil())
			namespaceName, err = services.FormatNamespace(createdCentral.Id)
			Expect(err).To(BeNil())
			Expect(constants.DinosaurRequestStatusAccepted.String()).To(Equal(createdCentral.Status))
		})

		It("should transition central's state to provisioning", func() {
			Eventually(func() string {
				Expect(createdCentral).NotTo(BeNil())
				provisioningCentral, err := client.GetCentral(createdCentral.Id)
				Expect(err).To(BeNil())
				return provisioningCentral.Status
			}).WithTimeout(waitTimeout).WithPolling(defaultPolling).Should(Equal(constants.DinosaurRequestStatusProvisioning.String()))
		})

		//TODO(create-ticket): fails because the namespace is not centralName anymore but `formatNamespace(dinosaurRequest.ID)`
		// and that is not accessible from a value `*public.CentralRequest`
		It("should create central namespace", func() {
			Eventually(func() error {
				ns := &v1.Namespace{}
				return k8sClient.Get(context.Background(), ctrlClient.ObjectKey{Name: namespaceName}, ns)
			}).WithTimeout(waitTimeout).WithPolling(defaultPolling).Should(Succeed())
		})

		It("should create central in its namespace on a managed cluster", func() {
			Eventually(func() error {
				central := &v1alpha1.Central{}
				return k8sClient.Get(context.Background(), ctrlClient.ObjectKey{Name: centralName, Namespace: namespaceName}, central)
			}).WithTimeout(waitTimeout).WithPolling(defaultPolling).Should(Succeed())
		})

		//TODO(ROX-11368): Add test to eventually reach ready state
		//TODO(ROX-11368): create test to check that Central and Scanner are healthy
		//TODO(ROX-11368): Create test to check Central is correctly exposed

		It("should transition central to deprovisioning state", func() {
			err = client.DeleteCentral(createdCentral.Id)
			Expect(err).To(Succeed())
			Eventually(func() string {
				deprovisioningCentral, err := client.GetCentral(createdCentral.Id)
				Expect(err).To(BeNil())
				return deprovisioningCentral.Status
			}).WithTimeout(waitTimeout).WithPolling(defaultPolling).Should(Equal(constants.DinosaurRequestStatusDeprovision.String()))
		})

		It("should delete central CR", func() {
			Eventually(func() bool {
				central := &v1alpha1.Central{}
				err := k8sClient.Get(context.Background(), ctrlClient.ObjectKey{Name: centralName, Namespace: centralName}, central)
				return apiErrors.IsNotFound(err)
			}).WithTimeout(waitTimeout).WithPolling(defaultPolling).Should(BeTrue())
		})

		It("should remove central namespace", func() {
			Eventually(func() bool {
				ns := &v1.Namespace{}
				err := k8sClient.Get(context.Background(), ctrlClient.ObjectKey{Name: namespaceName}, ns)
				return apiErrors.IsNotFound(err)
			}).WithTimeout(waitTimeout).WithPolling(defaultPolling).Should(BeTrue())
		})

	})
})
