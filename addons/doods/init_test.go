// Copyright 2020-2022 The OS-NVR Authors.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package doods

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"nvr/addons/doods/odrpc"
	"os"
	"testing"
)

func newTestConfig(t *testing.T) (string, func()) {
	tempDir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("could not create tempoary directory: %v", err)
	}

	cancelFunc := func() {
		os.RemoveAll(tempDir)
	}

	configPath := tempDir + "/doods.json"

	return configPath, cancelFunc
}

func TestReadConfig(t *testing.T) {
	t.Run("working", func(t *testing.T) {
		configPath, cancel := newTestConfig(t)
		defer cancel()

		file := `{ "ip": "test:8080" }`

		if err := os.WriteFile(configPath, []byte(file), 0o600); err != nil {
			t.Fatalf("could not write test file: %v", err)
		}

		actual, err := readConfig(configPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expected := "test:8080"
		if actual != expected {
			t.Fatalf("expected: %v, got: %v", expected, actual)
		}
	})
	t.Run("genFile", func(t *testing.T) {
		configPath, cancel := newTestConfig(t)
		defer cancel()

		if _, err := readConfig(configPath); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		file, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatalf("could not read addon file: %v", err)
		}

		actual := string(file)

		file, _ = json.Marshal(defaultConfig)
		expected := string(file)

		if actual != expected {
			t.Errorf("expected: %v, got: %v", expected, actual)
		}
	})
	t.Run("genFileErr", func(t *testing.T) {
		if _, err := readConfig("/dev/null/nil"); err == nil {
			t.Fatal("expected: error, got: nil")
		}
	})
	t.Run("unmarshalErr", func(t *testing.T) {
		configPath, cancel := newTestConfig(t)
		defer cancel()

		if err := os.WriteFile(configPath, []byte(""), 0o600); err != nil {
			t.Fatalf("could not write test file: %v", err)
		}

		if _, err := readConfig(configPath); err == nil {
			t.Fatal("expected: error, got: nil")
		}
	})
}

func TestNewFetcher(t *testing.T) {
	f := newFetcher("test")
	actual := f.url
	expected := "http://test/detectors"

	if actual != expected {
		t.Fatalf("expected: %v, got: %v", expected, actual)
	}
}

var testDetectors = []odrpc.Detector{
	{
		Name:     "1",
		Type:     "2",
		Model:    "3",
		Labels:   []string{"4"},
		Width:    5,
		Height:   6,
		Channels: 7,
	},
	{
		Name: "1x",
	},
}

func TestFetchDetectors(t *testing.T) {
	response, _ := json.Marshal(getDetectorsResponce{testDetectors})

	t.Run("working", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := io.WriteString(w, string(response)); err != nil {
				t.Fatalf("could not write response: %v", err)
			}
		}))
		defer ts.Close()

		f := fetcher{url: ts.URL}
		detectors, err := f.fetchDetectors()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		actual := fmt.Sprintf("%v", detectors)
		expected := fmt.Sprintf("%v", testDetectors)

		if actual != expected {
			t.Fatalf("expected: %v, got: %v", expected, actual)
		}
	})
	t.Run("createRequestErr", func(t *testing.T) {
		f := fetcher{url: string(rune(0x7f))}
		if _, err := f.fetchDetectors(); err == nil {
			t.Fatal("expected: error, got: nil")
		}
	})
	t.Run("sendErr", func(t *testing.T) {
		f := fetcher{url: ""}
		if _, err := f.fetchDetectors(); err == nil {
			t.Fatal("expected: error, got: nil")
		}
	})
	t.Run("unmarshalErr", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := io.WriteString(w, "nil"); err != nil {
				t.Fatalf("could not write response: %v", err)
			}
		}))
		defer ts.Close()

		f := fetcher{url: ts.URL}
		if _, err := f.fetchDetectors(); err == nil {
			t.Fatal("expected: error, got: nil")
		}
	})
}

func TestDetectorByName(t *testing.T) {
	t.Run("working", func(t *testing.T) {
		detectors = testDetectors
		d, err := detectorByName("1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		actual := fmt.Sprintf("%v", d)
		expected := fmt.Sprintf("%v", testDetectors[0])

		if actual != expected {
			t.Fatalf("expected: %v, got: %v", expected, actual)
		}
	})
	t.Run("error", func(t *testing.T) {
		detectors = testDetectors
		if _, err := detectorByName("nil"); err == nil {
			t.Fatal("expected: error, got: nil")
		}
	})
}
