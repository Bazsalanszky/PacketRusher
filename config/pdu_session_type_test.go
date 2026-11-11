/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2026 Balázs Toldi
 */

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Each ue.pdusessiontype value maps to its NAS PDU session type (TS 24.501 §9.11.4.11).
func TestPDUSessionTypeNAS(t *testing.T) {
	for typ, want := range map[PDUSessionType]uint8{
		"":                 1,
		PDUSessionIPv4:     1,
		PDUSessionIPv6:     2,
		PDUSessionIPv4v6:   3,
		PDUSessionEthernet: 5,
	} {
		_, known := pduSessionTypes[typ]
		require.True(t, known, "%q is a known type", typ)
		require.Equal(t, want, typ.NAS(), "NAS value of %q", typ)
	}
	_, known := pduSessionTypes["Unstructured"]
	require.False(t, known, "Unstructured is not offered")
}
