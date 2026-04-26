package oracle

import (
	"context"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/StackExchange/dnscontrol/v4/models"
	"github.com/StackExchange/dnscontrol/v4/pkg/diff"
	"github.com/StackExchange/dnscontrol/v4/pkg/printer"
	"github.com/StackExchange/dnscontrol/v4/pkg/providers"
	"github.com/ThalesGroup/crypto11"
	"golang.org/x/term"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/dns"
	"github.com/oracle/oci-go-sdk/v65/example/helpers"
)

var features = providers.DocumentationNotes{
	// The default for unlisted capabilities is 'Cannot'.
	// See providers/capabilities.go for the entire list of capabilities.
	providers.CanConcur:              providers.Unimplemented(),
	providers.CanGetZones:            providers.Can(),
	providers.CanOnlyDiff1Features:   providers.Can(),
	providers.CanUseAlias:            providers.Can(),
	providers.CanUseCAA:              providers.Can(),
	providers.CanUseDS:               providers.Cannot(), // should be supported, but getting 500s in tests
	providers.CanUseLOC:              providers.Unimplemented(),
	providers.CanUseNAPTR:            providers.Can(),
	providers.CanUsePTR:              providers.Can(),
	providers.CanUseSRV:              providers.Can(),
	providers.CanUseSSHFP:            providers.Can(),
	providers.CanUseTLSA:             providers.Can(),
	providers.DocCreateDomains:       providers.Can(),
	providers.DocDualHost:            providers.Can(),
	providers.DocOfficiallySupported: providers.Cannot(),
}

func init() {
	const providerName = "ORACLE"
	const providerMaintainer = "@kallsyms"
	fns := providers.DspFuncs{
		Initializer:   New,
		RecordAuditor: AuditRecords,
	}
	providers.RegisterDomainServiceProviderType(providerName, fns, features)
	providers.RegisterMaintainer(providerName, providerMaintainer)
}

type oracleProvider struct {
	client      dns.DnsClient
	compartment string
}

// pkcs11ConfigurationProvider implements common.ConfigurationProvider using a
// PKCS#11 token (e.g. YubiKey via OpenSC) for signing.
type pkcs11ConfigurationProvider struct {
	tenancy     string
	user        string
	region      string
	fingerprint string
	signer      crypto.Signer
}

func (p *pkcs11ConfigurationProvider) TenancyOCID() (string, error)  { return p.tenancy, nil }
func (p *pkcs11ConfigurationProvider) UserOCID() (string, error)     { return p.user, nil }
func (p *pkcs11ConfigurationProvider) Region() (string, error)       { return p.region, nil }
func (p *pkcs11ConfigurationProvider) KeyFingerprint() (string, error) { return p.fingerprint, nil }
func (p *pkcs11ConfigurationProvider) KeyID() (string, error) {
	return fmt.Sprintf("%s/%s/%s", p.tenancy, p.user, p.fingerprint), nil
}
func (p *pkcs11ConfigurationProvider) PrivateRSAKey() (crypto.Signer, error) { return p.signer, nil }
func (p *pkcs11ConfigurationProvider) AuthType() (common.AuthConfig, error) {
	return common.AuthConfig{}, nil
}

func getPIN() (string, error) {
	fmt.Fprint(os.Stderr, "PKCS#11 PIN: ")
	pin, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("reading PIN: %w", err)
	}
	return string(pin), nil
}

// newPKCS11ConfigurationProvider opens a PKCS#11 token and finds a key pair
// by CKA_ID (hex-encoded). Prompts for the token PIN via pinentry.
func newPKCS11ConfigurationProvider(tenancy, user, region, fingerprint, pkcs11Module, tokenLabel, keyIDHex string) (*pkcs11ConfigurationProvider, error) {
	pin, err := getPIN()
	if err != nil {
		return nil, err
	}

	p11, err := crypto11.Configure(&crypto11.Config{
		Path:       pkcs11Module,
		TokenLabel: tokenLabel,
		Pin:        pin,
	})
	if err != nil {
		return nil, fmt.Errorf("opening PKCS#11 token: %w", err)
	}

	keyID, err := hex.DecodeString(keyIDHex)
	if err != nil {
		p11.Close()
		return nil, fmt.Errorf("invalid pkcs11_key_id %q: %w", keyIDHex, err)
	}

	signer, err := p11.FindKeyPair(keyID, nil)
	if err != nil {
		p11.Close()
		return nil, fmt.Errorf("finding key pair: %w", err)
	}
	if signer == nil {
		p11.Close()
		return nil, fmt.Errorf("no key pair found with id %s", keyIDHex)
	}

	return &pkcs11ConfigurationProvider{
		tenancy:     tenancy,
		user:        user,
		region:      region,
		fingerprint: fingerprint,
		signer:      signer,
	}, nil
}

// New creates a new provider for Oracle Cloud DNS.
// If "private_key" is set in settings, it is used directly. Otherwise, the
// provider opens a PKCS#11 token for hardware-backed signing.
func New(settings map[string]string, _ json.RawMessage) (providers.DNSServiceProvider, error) {
	var configProvider common.ConfigurationProvider

	if settings["private_key"] != "" {
		configProvider = common.NewRawConfigurationProvider(
			settings["tenancy_ocid"],
			settings["user_ocid"],
			settings["region"],
			settings["fingerprint"],
			settings["private_key"],
			nil,
		)
	} else {
		pkcs11Module := settings["pkcs11_module"]
		if pkcs11Module == "" {
			return nil, fmt.Errorf("pkcs11_module is required when private_key is not set")
		}
		tokenLabel := settings["pkcs11_token_label"]
		if tokenLabel == "" {
			return nil, fmt.Errorf("pkcs11_token_label is required when private_key is not set")
		}
		keyID := settings["pkcs11_key_id"]
		if keyID == "" {
			return nil, fmt.Errorf("pkcs11_key_id is required when private_key is not set")
		}

		var err error
		configProvider, err = newPKCS11ConfigurationProvider(
			settings["tenancy_ocid"],
			settings["user_ocid"],
			settings["region"],
			settings["fingerprint"],
			pkcs11Module,
			tokenLabel,
			keyID,
		)
		if err != nil {
			return nil, fmt.Errorf("PKCS#11 setup: %w", err)
		}
	}

	client, err := dns.NewDnsClientWithConfigurationProvider(configProvider)
	if err != nil {
		return nil, err
	}

	// Set default retry policy to handle 429 automatically
	defaultRetryPolicy := common.DefaultRetryPolicy()
	client.SetCustomClientConfiguration(common.CustomClientConfiguration{
		RetryPolicy: &defaultRetryPolicy,
	})

	return &oracleProvider{
		client:      client,
		compartment: settings["compartment"],
	}, nil
}

// ListZones lists the zones on this account.
func (o *oracleProvider) ListZones() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	listResp, err := o.client.ListZones(ctx, dns.ListZonesRequest{
		CompartmentId: &o.compartment,
	})
	if err != nil {
		return nil, err
	}

	zones := make([]string, len(listResp.Items))
	for i, zone := range listResp.Items {
		zones[i] = *zone.Name
	}

	for listResp.OpcNextPage != nil {
		listResp, err = o.client.ListZones(ctx, dns.ListZonesRequest{
			CompartmentId: &o.compartment,
			Page:          listResp.OpcNextPage,
		})
		if err != nil {
			return nil, err
		}

		for _, zone := range listResp.Items {
			zones = append(zones, *zone.Name)
		}
	}

	return zones, nil
}

// EnsureZoneExists creates a zone if it does not exist.
func (o *oracleProvider) EnsureZoneExists(domain string, metadata map[string]string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	getResp, err := o.client.GetZone(ctx, dns.GetZoneRequest{
		ZoneNameOrId:  &domain,
		CompartmentId: &o.compartment,
	})
	if err == nil {
		return nil
	}
	if getResp.RawResponse.StatusCode != http.StatusNotFound {
		return err
	}

	_, err = o.client.CreateZone(ctx, dns.CreateZoneRequest{
		CreateZoneDetails: dns.CreateZoneDetails{
			CompartmentId: &o.compartment,
			Name:          &domain,
			ZoneType:      dns.CreateZoneDetailsZoneTypePrimary,
		},
	})
	if err != nil {
		return err
	}

	// poll until the zone is ready
	pollUntilAvailable := func(r common.OCIOperationResponse) bool {
		if converted, ok := r.Response.(dns.GetZoneResponse); ok {
			return converted.LifecycleState != dns.ZoneLifecycleStateActive
		}
		return true
	}
	getResp, err = o.client.GetZone(ctx, dns.GetZoneRequest{
		ZoneNameOrId:    &domain,
		CompartmentId:   &o.compartment,
		RequestMetadata: helpers.GetRequestMetadataWithCustomizedRetryPolicy(pollUntilAvailable),
	})

	return err
}

func (o *oracleProvider) GetNameservers(domain string) ([]*models.Nameserver, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	getResp, err := o.client.GetZone(ctx, dns.GetZoneRequest{
		ZoneNameOrId:  &domain,
		CompartmentId: &o.compartment,
	})
	if err != nil {
		return nil, err
	}

	nss := make([]string, len(getResp.Nameservers))
	for i, ns := range getResp.Nameservers {
		nss[i] = *ns.Hostname
	}

	nssNoStrip, err := models.ToNameservers(nss)
	if err != nil {
		nssStrip, err := models.ToNameserversStripTD(nss)
		if err != nil {
			return nil, errors.New("could not determine if trailing dots should be stripped or not")
		}

		return nssStrip, nil
	}

	return nssNoStrip, nil
}

func (o *oracleProvider) GetZoneRecords(dc *models.DomainConfig) (models.Records, error) {
	zone := dc.Name

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	records := models.Records{}

	request := dns.GetZoneRecordsRequest{
		ZoneNameOrId:  &zone,
		CompartmentId: &o.compartment,
	}

	for {
		getResp, err := o.client.GetZoneRecords(ctx, request)
		if err != nil {
			return nil, err
		}

		for _, record := range getResp.Items {
			// Hide SOAs
			if *record.Rtype == "SOA" {
				continue
			}

			rc := &models.RecordConfig{
				Type:     *record.Rtype,
				TTL:      uint32(*record.Ttl),
				Original: record,
			}
			rc.SetLabelFromFQDN(*record.Domain, zone)

			switch rc.Type {
			case "ALIAS":
				err = rc.SetTarget(*record.Rdata)
			default:
				err = rc.PopulateFromString(*record.Rtype, *record.Rdata, zone)
			}

			if err != nil {
				return nil, err
			}

			records = append(records, rc)
		}

		if getResp.OpcNextPage == nil {
			break
		}

		request.Page = getResp.OpcNextPage
	}

	return records, nil
}

// GetZoneRecordsCorrections returns a list of corrections that will turn existing records into dc.Records.
func (o *oracleProvider) GetZoneRecordsCorrections(dc *models.DomainConfig, existingRecords models.Records) ([]*models.Correction, int, error) {
	var err error

	// Ensure we don't emit changes for attempted modification of built-in apex NSs
	for _, rec := range dc.Records {
		if rec.Type != "NS" {
			continue
		}

		recNS := rec.GetTargetField()
		if rec.GetLabel() == "@" && strings.HasSuffix(recNS, "dns.oraclecloud.com.") {
			printer.Warnf("Oracle Cloud does not allow changes to built-in apex NS records. Ignoring change to %s...\n", recNS)
			continue
		}

		if rec.GetLabel() == "@" && rec.TTL != 86400 {
			printer.Warnf("Oracle Cloud forces TTL=86400 for NS records. Ignoring configured TTL of %d for %s\n", rec.TTL, recNS)
			rec.TTL = 86400
		}
	}

	toReport, create, dels, modify, actualChangeCount, err := diff.NewCompat(dc).IncrementalDiff(existingRecords)
	if err != nil {
		return nil, 0, err
	}
	// Start corrections with the reports
	corrections := diff.GenerateMessageCorrections(toReport)

	/*
		Oracle's API doesn't have a way to update an existing record.
		You can either update an existing RRSet, Domain (FQDN), or Zone in which you have to supply
		the entire desired state, or you can patch specifying ADD/REMOVE actions.
		Oracle's API is also increadibly slow, so updating individual RRSets is unbearably slow
		for any size zone.
	*/

	var desc strings.Builder
	createRecords := models.Records{}
	deleteRecords := models.Records{}

	if len(create) > 0 {
		for _, rec := range create {
			createRecords = append(createRecords, rec.Desired)
			desc.WriteString(rec.String() + "\n")
		}
	}

	if len(dels) > 0 {
		for _, rec := range dels {
			deleteRecords = append(deleteRecords, rec.Existing)
			desc.WriteString(rec.String() + "\n")
		}
	}

	if len(modify) > 0 {
		for _, rec := range modify {
			createRecords = append(createRecords, rec.Desired)
			deleteRecords = append(deleteRecords, rec.Existing)
			desc.WriteString(rec.String() + "\n")
		}
	}

	// There were corrections. Send them as one big batch:
	if len(createRecords) > 0 || len(deleteRecords) > 0 {
		corrections = append(corrections, &models.Correction{
			Msg: desc.String(),
			F: func() error {
				return o.patch(createRecords, deleteRecords, dc.Name)
			},
		})
	}

	return corrections, actualChangeCount, nil
}

func (o *oracleProvider) patch(createRecords, deleteRecords models.Records, domain string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	patchReq := dns.PatchZoneRecordsRequest{
		ZoneNameOrId:  &domain,
		CompartmentId: &o.compartment,
	}

	ops := make([]dns.RecordOperation, 0, len(createRecords)+len(deleteRecords))

	for _, rec := range deleteRecords {
		ops = append(ops, convertToRecordOperation(rec, dns.RecordOperationOperationRemove))
	}
	for _, rec := range createRecords {
		ops = append(ops, convertToRecordOperation(rec, dns.RecordOperationOperationAdd))
	}

	for batchStart := 0; batchStart < len(ops); batchStart += 100 {
		batchEnd := min(batchStart+100, len(ops))
		patchReq.Items = ops[batchStart:batchEnd]

		_, err := o.client.PatchZoneRecords(ctx, patchReq)
		if err != nil {
			return err
		}
	}

	return nil
}

func convertToRecordOperation(rec *models.RecordConfig, op dns.RecordOperationOperationEnum) dns.RecordOperation {
	if rec.Original != nil {
		return dns.RecordOperation{
			RecordHash: rec.Original.(dns.Record).RecordHash,
			Operation:  op,
		}
	}

	fqdn := rec.GetLabelFQDN()
	rtype := rec.Type
	rdata := rec.GetTargetCombined()
	ttl := int(rec.TTL)

	return dns.RecordOperation{
		Domain:    &fqdn,
		Rtype:     &rtype,
		Rdata:     &rdata,
		Ttl:       &ttl,
		Operation: op,
	}
}
