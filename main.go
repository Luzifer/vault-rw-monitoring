package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Luzifer/rconfig"
	"github.com/hashicorp/vault/api"
	uuid "github.com/satori/go.uuid"
)

const (
	eventURL = "https://events.pagerduty.com/generic/2010-04-15/create_event.json"
)

type alarmState uint

const (
	stateUnknown alarmState = iota
	stateOK
	stateFailed
)

var (
	cfg = struct {
		VaultAddress string `flag:"vault-address" default:"http://localhost:8200" env:"VAULT_ADDR" description:"Address of the Vault instance"`
		VaultKey     string `flag:"vault-key" default:"/secret/vault-rw-monitoring" env:"VAULT_KEY" description:"Key to use for read/write test"`
		VaultToken   string `flag:"vault-token" default:"" env:"VAULT_TOKEN" description:"Token to access the key specified in vault-key"`

		PagerDutyIntegrationKey string `flag:"pagerduty-key" default:"" env:"PAGERDUTY_KEY" description:"Integration key for the Generic API service in PagerDuty"`

		CheckInterval  time.Duration `flag:"interval" default:"30s" env:"INTERVAL" description:"Interval to execute the test"`
		AlertThreshold int           `flag:"threshold" default:"4" env:"THRESHOLD" description:"How often to fail before sending PagerDuty alerts"`

		VersionAndExit bool `flag:"version" default:"false" description:"Prints current version and exits"`
		Verbose        bool `flag:"verbose,v" default:"false" description:"Enable verbose output"`
	}{}

	version             = "dev"
	currentAlertCounter int
	alertActive         alarmState
)

func init() {
	if err := rconfig.Parse(&cfg); err != nil {
		log.Fatalf("Unable to parse commandline options: %s", err)
	}

	if cfg.VersionAndExit {
		fmt.Printf("vault-rw-monitoring %s\n", version)
		os.Exit(0)
	}

	if cfg.VaultToken == "" {
		log.Fatalf("You need to provide a vault-token")
	}

	if cfg.PagerDutyIntegrationKey == "" {
		log.Fatalf("You need to provide a PagerDuty service key")
	}
}

func main() {
	log.Printf("vault-rw-monitoring %s started with check interval of %s and threshold of %d", version, cfg.CheckInterval, cfg.AlertThreshold)

	for range time.Tick(cfg.CheckInterval) {
		if err := executeTest(); err != nil {
			currentAlertCounter++
			log.Printf("Something went wrong, counter is now at %d / %d", currentAlertCounter, cfg.AlertThreshold)
			log.Printf("Recorded error: %s", err)
		} else {
			if cfg.Verbose {
				log.Printf("Successful test.")
			}
			if err := sendPagerDutyAlert(false); err != nil {
				log.Printf("Was not able to resolve PagerDuty alert: %s", err)
				continue
			}
		}

		if currentAlertCounter >= cfg.AlertThreshold {
			if err := sendPagerDutyAlert(true); err != nil {
				log.Printf("Was not able to send PagerDuty alert: %s", err)
				continue
			}
		}
	}

	log.Fatalf("vault-rw-monitoring exitted unexpectedly")
}

func executeTest() error {
	client, err := api.NewClient(&api.Config{
		Address: cfg.VaultAddress,
	})
	if err != nil {
		return err
	}

	client.SetToken(cfg.VaultToken)

	expectedValue := uuid.NewV4().String()
	if _, err := client.Logical().Write(strings.TrimLeft(cfg.VaultKey, "/"), map[string]interface{}{
		"value": expectedValue,
	}); err != nil {
		return fmt.Errorf("Could not write key: %s", err)
	}

	data, err := client.Logical().Read(strings.TrimLeft(cfg.VaultKey, "/"))
	if err != nil {
		return fmt.Errorf("Could not read key: %s", err)
	}

	if v, ok := data.Data["value"]; !ok || v.(string) != expectedValue {
		return errors.New("Did not find expected value in key.")
	}

	if _, err := client.Logical().Delete(strings.TrimLeft(cfg.VaultKey, "/")); err != nil {
		return fmt.Errorf("Could not delete key: %s", err)
	}

	return nil
}

type pagerDutyEvent struct {
	ServiceKey  string                 `json:"service_key"`
	EventType   string                 `json:"event_type"`
	IncidentKey string                 `json:"incident_key,omitempty"`
	Description string                 `json:"description"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Client      string                 `json:"client,omitempty"`
	ClientURL   string                 `json:"client_url,omitempty"`
	Contexts    []pagerDutyContext     `json:"contexts,omitempty"`
}

type pagerDutyContext struct {
	Type string `json:"type"`
	Href string `json:"href,omitempty"`
	Text string `json:"text,omitempty"`
	Src  string `json:"src,omitempty"`
}

func sendPagerDutyAlert(trigger bool) error {
	if (trigger && alertActive == stateFailed) || (!trigger && alertActive == stateOK) {
		return nil
	}

	obj := pagerDutyEvent{
		ServiceKey:  cfg.PagerDutyIntegrationKey,
		EventType:   "trigger",
		IncidentKey: generateIncidentKey(),
		Description: fmt.Sprintf("Vault instance at %s failed %d consecutive tests of the vault-rw-monitoring", cfg.VaultAddress, cfg.AlertThreshold),
		Client:      fmt.Sprintf("vault-rw-monitoring %s", version),
	}

	if !trigger {
		obj.EventType = "resolve"
	}

	buf := bytes.NewBuffer([]byte{})
	if err := json.NewEncoder(buf).Encode(obj); err != nil {
		return err
	}

	resp, err := http.Post(eventURL, "application/json", buf)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("Experienced unexected status code: %d", resp.StatusCode)
	}

	if trigger {
		alertActive = stateFailed
	} else {
		alertActive = stateOK
	}
	currentAlertCounter = 0

	return nil
}

func generateIncidentKey() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte("vault-rw-monitoring of "+cfg.VaultAddress)))
}
