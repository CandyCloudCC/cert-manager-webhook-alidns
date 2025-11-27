package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	alidns "github.com/alibabacloud-go/alidns-20150109/v4/client"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	k8smeta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	SolverName    = "alidns"
	TxtRecordType = "TXT"
)

var GroupName = os.Getenv("GROUP_NAME")

type solverConfig struct {
	AccessKeyIdRef     *cmmeta.SecretKeySelector `json:"accessKeyIdRef,omitempty"`
	AccessKeySecretRef *cmmeta.SecretKeySelector `json:"accessKeySecretRef,omitempty"`
	Endpoint           string                    `json:"endpoint,omitempty"`
}

// Solver implements cert-manager's webhook.Solver interface.
type AlidnsSolver struct {
	kubeClient kubernetes.Interface
	recordIDs  sync.Map
}

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	cmd.RunWebhookServer(GroupName, &AlidnsSolver{})
}

// Name returns the name used in Issuer resources.
func (s *AlidnsSolver) Name() string {
	return SolverName
}

// Initialize is called once at startup.
func (s *AlidnsSolver) Initialize(kubeClientConfig *rest.Config, _ <-chan struct{}) error {
	if kubeClientConfig == nil {
		return fmt.Errorf("kubernetes client configuration is required")
	}
	client, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize kubernetes client: %w", err)
	}
	s.kubeClient = client
	return nil
}

// Present provisions the TXT record.
func (s *AlidnsSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	ctx := context.Background()
	client, err := s.newAliDNSClient(ctx, ch)
	if err != nil {
		return err
	}

	domain, rr, err := extractRecordDetails(ch)
	if err != nil {
		return err
	}

	recordID, err := ensureTXTRecord(client, domain, rr, ch.Key)
	if err != nil {
		return err
	}

	s.recordIDs.Store(cacheKey(ch), recordID)
	return nil
}

// CleanUp removes the TXT record used during validation.
func (s *AlidnsSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	ctx := context.Background()
	client, err := s.newAliDNSClient(ctx, ch)
	if err != nil {
		return err
	}

	domain, rr, err := extractRecordDetails(ch)
	if err != nil {
		return err
	}

	key := cacheKey(ch)
	if cached, ok := s.recordIDs.Load(key); ok {
		if recordID, _ := cached.(string); recordID != "" {
			if err := deleteRecord(client, recordID); err == nil {
				s.recordIDs.Delete(key)
				return nil
			}
		}
	}

	records, err := lookupRecords(client, domain, rr, ch.Key)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		return nil
	}

	var combined error
	for _, record := range records {
		if record == nil || record.RecordId == nil {
			continue
		}
		if err := deleteRecord(client, *record.RecordId); err != nil {
			combined = errors.Join(combined, err)
		}
	}

	if combined != nil {
		return combined
	}

	s.recordIDs.Delete(key)
	return nil
}

func (s *AlidnsSolver) resolveCredentials(ctx context.Context, ch *v1alpha1.ChallengeRequest) (config *openapi.Config, err error) {
	if ch.Config == nil || len(ch.Config.Raw) == 0 {
		return nil, fmt.Errorf("solver config 为空")
	}

	sConfig := &solverConfig{}
	if err := json.Unmarshal(ch.Config.Raw, sConfig); err != nil {
		return nil, fmt.Errorf("error decoding solver config: %w", err)
	}

	if sConfig.AccessKeyIdRef == nil {
		return nil, fmt.Errorf("AccessKey ID is required")

	}

	if sConfig.AccessKeySecretRef == nil {
		return nil, fmt.Errorf("AccessKey Secret is required")
	}

	accessKeyId, err := s.secretValue(ctx, ch.ResourceNamespace, sConfig.AccessKeyIdRef)
	if err != nil {
		return nil, err
	}

	accessKeySecret, err := s.secretValue(ctx, ch.ResourceNamespace, sConfig.AccessKeySecretRef)
	if err != nil {
		return nil, err
	}

	if accessKeyId == "" || accessKeySecret == "" {
		return nil, fmt.Errorf("alidns credentials are required; set secret references in solver config")
	}

	return &openapi.Config{AccessKeyId: tea.String(accessKeyId), AccessKeySecret: tea.String(accessKeySecret), Endpoint: tea.String(sConfig.Endpoint)}, nil
}

func (s *AlidnsSolver) secretValue(ctx context.Context, namespace string, selector *cmmeta.SecretKeySelector) (string, error) {
	if selector == nil {
		return "", nil
	}
	if s.kubeClient == nil {
		return "", fmt.Errorf("kubernetes client not initialized")
	}
	secret, err := s.kubeClient.CoreV1().Secrets(namespace).Get(ctx, selector.Name, k8smeta.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to read secret %s/%s: %w", namespace, selector.Name, err)
	}

	data, ok := secret.Data[selector.Key]
	if !ok {
		return "", fmt.Errorf("secret %s/%s missing key %s", namespace, selector.Name, selector.Key)
	}

	return strings.TrimSpace(string(data)), nil
}

func (s *AlidnsSolver) newAliDNSClient(ctx context.Context, ch *v1alpha1.ChallengeRequest) (*alidns.Client, error) {
	config, err := s.resolveCredentials(ctx, ch)
	if err != nil {
		return nil, fmt.Errorf("failed to construct alibabacloud Credentials")
	}

	if *config.Endpoint == "" {
		config.Endpoint = tea.String("alidns.aliyuncs.com")
	}

	client, err := alidns.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to construct alidns client: %w", err)
	}
	return client, nil
}

func ensureTXTRecord(client *alidns.Client, domain, rr, value string) (string, error) {
	existing, err := lookupRecords(client, domain, rr, value)
	if err != nil {
		return "", err
	}
	for _, record := range existing {
		if record != nil && record.RecordId != nil {
			return *record.RecordId, nil
		}
	}

	req := &alidns.AddDomainRecordRequest{}
	req.SetDomainName(domain)
	req.SetRR(rr)
	req.SetType(TxtRecordType)
	req.SetValue(value)

	resp, err := client.AddDomainRecord(req)
	if err != nil {
		return "", fmt.Errorf("failed to add TXT record %s.%s: %w", rr, domain, err)
	}
	if resp == nil || resp.Body == nil || resp.Body.RecordId == nil {
		return "", fmt.Errorf("alidns add domain record returned empty response")
	}
	return *resp.Body.RecordId, nil
}

func lookupRecords(client *alidns.Client, domain, rr, value string) ([]*alidns.DescribeDomainRecordsResponseBodyDomainRecordsRecord, error) {
	var matches []*alidns.DescribeDomainRecordsResponseBodyDomainRecordsRecord

	pageSize := int64(100)
	for page := int64(1); ; page++ {
		req := &alidns.DescribeDomainRecordsRequest{}
		req.SetDomainName(domain)
		req.SetRRKeyWord(rr)
		req.SetType(TxtRecordType)
		req.SetPageNumber(page)
		req.SetPageSize(pageSize)

		resp, err := client.DescribeDomainRecords(req)
		if err != nil {
			return nil, fmt.Errorf("failed to list records for %s.%s: %w", rr, domain, err)
		}
		if resp.Body == nil || resp.Body.DomainRecords == nil {
			break
		}

		for _, record := range resp.Body.DomainRecords.Record {
			if record == nil || record.RR == nil || record.Type == nil || !strings.EqualFold(*record.Type, TxtRecordType) {
				continue
			}
			if *record.RR != rr {
				continue
			}
			if value != "" && (record.Value == nil || *record.Value != value) {
				continue
			}
			matches = append(matches, record)
		}

		total := int64(0)
		if resp.Body.TotalCount != nil {
			total = *resp.Body.TotalCount
		}
		if page*pageSize >= total || len(resp.Body.DomainRecords.Record) == 0 {
			break
		}
	}

	return matches, nil
}

func deleteRecord(client *alidns.Client, recordID string) error {
	if recordID == "" {
		return nil
	}
	req := &alidns.DeleteDomainRecordRequest{}
	req.SetRecordId(recordID)
	if _, err := client.DeleteDomainRecord(req); err != nil {
		return fmt.Errorf("failed to delete record %s: %w", recordID, err)
	}
	return nil
}

func cacheKey(ch *v1alpha1.ChallengeRequest) string {
	return fmt.Sprintf("%s|%s", ch.ResolvedFQDN, ch.Key)
}

func extractRecordDetails(ch *v1alpha1.ChallengeRequest) (string, string, error) {
	zone := trimDot(ch.ResolvedZone)
	if zone == "" {
		zone = trimDot(ch.DNSName)
	}
	if zone == "" {
		return "", "", fmt.Errorf("resolved zone was empty")
	}

	fqdn := trimDot(ch.ResolvedFQDN)
	if fqdn == "" {
		fqdn = fmt.Sprintf("_acme-challenge.%s", zone)
	}

	if fqdn == zone {
		return zone, "@", nil
	}

	suffix := "." + zone
	if strings.HasSuffix(fqdn, suffix) {
		rr := strings.TrimSuffix(fqdn, suffix)
		rr = strings.TrimSuffix(rr, ".")
		if rr == "" {
			rr = "@"
		}
		return zone, rr, nil
	}

	return "", "", fmt.Errorf("fqdn %q does not belong to zone %q", fqdn, zone)
}

func trimDot(value string) string {
	return strings.TrimSuffix(strings.TrimSpace(value), ".")
}
