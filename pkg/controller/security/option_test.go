/*
 * Copyright The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package security

import (
	"testing"
	"time"
)

func TestNewSecurityOptions(t *testing.T) {
	opts := NewSecurityOptions()
	if opts == nil {
		t.Fatal("expected non-nil security options")
	}
	if opts.WorkloadRSAKeySize != 2048 {
		t.Errorf("expected default WorkloadRSAKeySize 2048, got %d", opts.WorkloadRSAKeySize)
	}
	if opts.Pkcs8Keys != false {
		t.Errorf("expected default Pkcs8Keys false, got %v", opts.Pkcs8Keys)
	}
	if opts.ECCSigAlg != "" {
		t.Errorf("expected default ECCSigAlg empty, got %q", opts.ECCSigAlg)
	}
	if opts.ECCCurve != "P256" {
		t.Errorf("expected default ECCCurve P256, got %q", opts.ECCCurve)
	}
	if opts.SecretTTL != 24*time.Hour {
		t.Errorf("expected default SecretTTL 24h, got %v", opts.SecretTTL)
	}
}
