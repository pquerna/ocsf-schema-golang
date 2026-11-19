//go:build gen_json_schema

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

func main() {
	versions := []string{"1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.8"}

	for _, version := range versions {
		classlist := fmt.Sprintf(
			"../schema/v%s-schema-class-list.json",
			version,
		)

		d, err := os.ReadFile(classlist)
		if err != nil {
			log.Fatalf("reading %s: %w", classlist, err)
			return
		}

		cl := map[string]interface{}{}
		err = json.Unmarshal(d, &cl)
		if err != nil {
			log.Fatalf("parsing schema-class-list.json: %w", err)
			return
		}
		// The 1.8 class list also contains abstract classes without a UID.
		// These cannot represent events and the schema server does not expose them.
		var classes map[string]struct {
			UID int `json:"uid"`
		}
		if version == "1.8" {
			data, err := os.ReadFile("../schema/v1.8-schema.json")
			if err != nil {
				log.Fatal(err)
			}
			var snapshot struct {
				Classes map[string]struct {
					UID int `json:"uid"`
				} `json:"classes"`
			}
			if err := json.Unmarshal(data, &snapshot); err != nil {
				log.Fatal(err)
			}
			classes = snapshot.Classes
		}
		for _, v := range cl {
			vv := v.([]interface{})
			for _, vvx := range vv {
				className := vvx.(string)
				if classes != nil {
					class, ok := classes[className]
					if !ok {
						log.Fatalf("class %s missing from snapshot", className)
					}
					if class.UID == 0 {
						log.Printf("skipping abstract class %s", className)
						continue
					}
				}
				err = fetchSchema(className, version)
				if err != nil {
					log.Fatalf("failed fetching %s: %w", className, err)
					return
				}
			}
		}
	}
}

func fetchSchema(className string, version string) error {
	fullVersion := fmt.Sprintf("%s.0", version)

	ux := url.URL{
		Scheme: "https",
		Host:   "schema.ocsf.io",
		Path:   path.Join("schema", fullVersion, "classes", className),
		RawQuery: url.Values{
			"profiles": []string{
				strings.Join([]string{
					"cloud",
					"container",
					"data_classification",
					"datetime",
					"host",
					"incident",
					"load_balancer",
					"network_proxy",
					// osint -- skipped since it marks osint field as required.
					"security_control",
					"trace",
				}, ","),
			},
		}.Encode(),
	}

	if base := os.Getenv("OCSF_SCHEMA_BASE_URL"); base != "" {
		baseURL, err := url.Parse(base)
		if err != nil {
			return fmt.Errorf("invalid OCSF_SCHEMA_BASE_URL: %w", err)
		}
		ux.Scheme, ux.Host = baseURL.Scheme, baseURL.Host
		ux.Path = path.Join(baseURL.Path, "classes", className)
	}
	// Windows classes live under the server's extension namespace in 1.8.
	if version == "1.8" {
		switch className {
		case "registry_key_query", "registry_value_activity", "registry_key_activity", "prefetch_query", "windows_service_activity", "windows_resource_activity", "registry_value_query":
			ux.Path = path.Join(path.Dir(ux.Path), "win", className)
		}
	}
	log.Printf("fetching %s/%s from %s", className, version, ux.String())

	// 	https://schema.ocsf.io/schema/1.2.0/classes/web_resources_activity?profiles=
	diskPath := filepath.Join(version, "jsonschema", "classes_"+className+".json.zst")
	dpAbs, err := filepath.Abs(diskPath)
	if err != nil {
		return fmt.Errorf("fetchSchema: filepath.Abs failed: %w", err)
	}

	if _, err := os.Stat(diskPath); err == nil {
		log.Printf("skipping %s", diskPath)
		return nil
	}

	diskURL := url.URL{
		Scheme: "file",
		Path:   filepath.ToSlash(dpAbs),
	}

	req, err := http.NewRequest("GET", ux.String(), nil)
	if err != nil {
		return fmt.Errorf("fetchSchema: http.NewRequest failed: %w", err)
	}
	startTime := time.Now()
	req.Header.Set("User-Agent", "ocsf-schema-golang/fetch-schema")
	client := &http.Client{Timeout: 20 * time.Second}
	var resp *http.Response
	for attempt := 0; attempt < 3; attempt++ {
		resp, err = client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		}
		if err == nil {
			err = fmt.Errorf("HTTP status %s", resp.Status)
			resp.Body.Close()
		}
		if attempt < 2 {
			log.Printf("fetch failed: %v; retrying", err)
			time.Sleep(time.Duration(1<<attempt) * time.Second)
		}
	}
	if err != nil {
		return fmt.Errorf("fetchSchema: http fetch failed: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(
		http.MaxBytesReader(nil, resp.Body, 1024*1024*10),
	)
	if err != nil {
		return fmt.Errorf("fetchSchema: http read all failed: %w", err)
	}
	elapsed := time.Since(startTime)
	log.Printf("fetchSchema: http fetch took %s", elapsed)
	buf := &bytes.Buffer{}
	err = json.Indent(buf, data, "", "  ")
	if err != nil {
		return fmt.Errorf("fetchSchema: json Ident failed: %w", err)
	}

	startTime = time.Now()
	_, err = jsonschema.CompileString(diskURL.String(), buf.String())
	if err != nil {
		return fmt.Errorf("fetchSchema: jsonschema.CompileString failed: %w", err)
	}
	elapsed = time.Since(startTime)
	log.Printf("fetchSchema: jsonschema compile took %s", elapsed)

	startTime = time.Now()
	out := &bytes.Buffer{}
	enc, err := zstd.NewWriter(out)
	if err != nil {
		return err
	}
	_, err = io.Copy(enc, buf)
	if err != nil {
		enc.Close()
		return err
	}
	err = enc.Close()
	if err != nil {
		return err
	}

	err = os.WriteFile(diskPath, out.Bytes(), 0644)
	if err != nil {
		return fmt.Errorf("fetchSchema: write file failed: %w", err)
	}

	return nil
}
