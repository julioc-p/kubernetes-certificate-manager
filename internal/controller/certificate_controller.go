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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"strconv"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	certsk8ciov1 "certs.k8c.io/certificate-manager/api/v1"
)

// CertificateReconciler reconciles a Certificate object
type CertificateReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=certs.k8c.io.certs.k8c.io,resources=certificates,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=certs.k8c.io.certs.k8c.io,resources=certificates/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=certs.k8c.io.certs.k8c.io,resources=certificates/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Certificate object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/reconcile
func (r *CertificateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	cert := certsk8ciov1.Certificate{}

	if err := r.Get(ctx, req.NamespacedName, &cert); err != nil {
		log.Error(err, "unable to fetch Certificate")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	secretName := cert.Spec.SecretRef.Name
	secret := &v1.Secret{}
	err := r.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: secretName}, secret)
	if err == nil {
		r.Delete(ctx, secret)
	}

	errorSecretCreation := createSecret(r, ctx, secretName, cert.Spec.DnsName, cert.Spec.Validity, req.Namespace)
	if errorSecretCreation != nil {
		log.Error(errorSecretCreation, "unable to create secret")
		return ctrl.Result{}, errorSecretCreation
	}

	return ctrl.Result{}, nil
}

func createSecret(r *CertificateReconciler, ctx context.Context, secretName string, dnsName string, validity string, namespace string) error {
	// Parse the validity and generate the certificate
	t, err := parseValidity(validity)
	if err != nil {
		return err
	}

	certificateTemplate := createCertificateTemplate(dnsName, t)

	// Generate public and private key
	priv, pub, err := generateKeyPair()
	if err != nil {
		return err
	}

	// Create a self-signed certificate
	certPEM, privPEM, err := createSelfSignedCert(certificateTemplate, priv, pub)
	if err != nil {
		return err
	}

	// Create a Kubernetes secret object
	secret := createK8sSecret(secretName, namespace, certPEM, privPEM)

	return r.Client.Create(ctx, secret)
}

func createCertificateTemplate(dnsName string, validity time.Duration) x509.Certificate {
	return x509.Certificate{
		DNSNames:     []string{dnsName},
		NotAfter:     time.Now().Add(validity),
		SerialNumber: big.NewInt(2024),
	}
}

func generateKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	return priv, &priv.PublicKey, nil
}

func createSelfSignedCert(template x509.Certificate, priv *rsa.PrivateKey, pub *rsa.PublicKey) ([]byte, []byte, error) {
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		return nil, nil, err
	}

	// Convert private key to PEM format
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	// Convert certificate to PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return certPEM, privPEM, nil
}

func createK8sSecret(secretName, namespace string, certPEM, privPEM []byte) *v1.Secret {
	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
		},
		Type: v1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": certPEM, // Certificate
			"tls.key": privPEM, // Private key
		},
	}
}

func parseValidity(validity string) (time.Duration, error) {
	// parse the validity string
	// validity string is in the format of "360d" for 360 days
	// return the time.Duration of the validity
	days, err := strconv.Atoi(validity[:len(validity)-1])
	hours := 24 * days
	return time.Duration(hours) * time.Hour, err
}

// SetupWithManager sets up the controller with the Manager.
func (r *CertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certsk8ciov1.Certificate{}).
		Complete(r)
}
