/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	certsk8ciov1 "certs.k8c.io/certificate-manager/api/v1"
)

var _ = Describe("Certificate Controller", func() {
	// Define utility constants for object names and testing timeouts/durations.
	const (
		CertificateName      = "test-certificate"
		CertificateNamespace = "default"
		DnsName              = "test-certificate.com"
		Validity             = "360d"

		timeout  = time.Second * 10
		duration = time.Second * 10
		interval = time.Millisecond * 250
	)

	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default", // TODO(user):Modify as needed
		}
		certificate := &certsk8ciov1.Certificate{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind Certificate")
			err := k8sClient.Get(ctx, typeNamespacedName, certificate)
			if err != nil && errors.IsNotFound(err) {
				resource := &certsk8ciov1.Certificate{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "certs.k8c.io/v1",
						Kind:       "Certificate",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      CertificateName,
						Namespace: CertificateNamespace,
					},
					Spec: certsk8ciov1.CertificateSpec{
						DnsName:  DnsName,
						Validity: Validity,
						SecretRef: certsk8ciov1.SecretRef{
							Name: "test-secret",
						},
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}

			certificateLookupKey := types.NamespacedName{Name: CertificateName, Namespace: CertificateNamespace}
			createdCertificateResource := &certsk8ciov1.Certificate{}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, certificateLookupKey, createdCertificateResource)
				return err == nil
			}, timeout, interval).Should(BeTrue())
		})

		AfterEach(func() {
			// TODO(user): Cleanup logic after each test, like removing the resource instance.
			certificateLookupKey := types.NamespacedName{Name: CertificateName, Namespace: CertificateNamespace}
			createdCertificateResource := &certsk8ciov1.Certificate{}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, certificateLookupKey, createdCertificateResource)
				return err == nil
			}, timeout, interval).Should(BeTrue())

			By("Cleanup the specific resource instance Certificate")
			k8sClient.Delete(ctx, createdCertificateResource)
		})

		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			controllerReconciler := &CertificateReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			// TODO(user): Add more specific assertions depending on your controller's reconciliation logic.
			// Example: If you expect a certain status condition after reconciliation, verify it here.
		})

		It("should create a secret with the certificate", func() {
			By("Creating a new Certificate resource")

			certificateLookupKey := types.NamespacedName{Name: CertificateName, Namespace: CertificateNamespace}
			createdCertificateResource := &certsk8ciov1.Certificate{}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, certificateLookupKey, createdCertificateResource)
				return err == nil
			}, timeout, interval).Should(BeTrue())

			By("checking if the secret was created")
			secretLookupKey := types.NamespacedName{Name: "test-secret", Namespace: CertificateNamespace}
			createdSecret := &corev1.Secret{}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, secretLookupKey, createdSecret)
				return err == nil
			}, timeout, interval).Should(BeTrue())

			Expect(createdSecret.Type).Should(Equal(corev1.SecretTypeTLS))

			Expect(createdSecret.Data).Should(HaveKey("tls.crt"))
			Expect(createdSecret.Data).Should(HaveKey("tls.key"))

		})

		It("should not throw errors when two certificates share same secret reference", func() {
			By("Creating a new Certificate resource")
			resource := &certsk8ciov1.Certificate{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "certs.k8c.io/v1",
					Kind:       "Certificate",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      CertificateName + "-new",
					Namespace: CertificateNamespace,
				},
				Spec: certsk8ciov1.CertificateSpec{
					DnsName:  DnsName,
					Validity: Validity,
					SecretRef: certsk8ciov1.SecretRef{
						Name: "test-secret",
					},
				},
			}
			Expect(k8sClient.Create(ctx, resource)).To(Succeed())

		})

		It("should delete the secret when the certificate is deleted", func() {
			By("Creating a new Certificate resource")
			resource := &certsk8ciov1.Certificate{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "certs.k8c.io/v1",
					Kind:       "Certificate",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "certificate-to-delete",
					Namespace: CertificateNamespace,
				},
				Spec: certsk8ciov1.CertificateSpec{
					DnsName:  "new-dns-name.com",
					Validity: Validity,
					SecretRef: certsk8ciov1.SecretRef{
						Name: "test-secret2",
					},
				},
			}

			Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			certificateLookupKey := types.NamespacedName{Name: "certificate-to-delete", Namespace: CertificateNamespace}
			createdCertificateResource := &certsk8ciov1.Certificate{}

			Eventually(func() bool {
				err := k8sClient.Get(ctx, certificateLookupKey, createdCertificateResource)
				return err == nil
			}, timeout, interval).Should(BeTrue())

			By("checking if the secret was created")
			secretLookupKey := types.NamespacedName{Name: "test-secret2}", Namespace: CertificateNamespace}
			createdSecret := &corev1.Secret{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, secretLookupKey, createdSecret)
				return err == nil
			}, timeout, interval).Should(BeTrue())

			By("deleting the Certificate resource")
			Expect(k8sClient.Delete(ctx, createdCertificateResource)).To(Succeed())

			By("checking if the secret was deleted")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, secretLookupKey, createdSecret)
				return errors.IsNotFound(err)
			}).Should(BeTrue())

		})
	})
})
