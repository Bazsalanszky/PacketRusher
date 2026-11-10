/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 * © Copyright 2026 Valentin D'Emmanuele
 */
package ue_mobility_management

import (
	"my5G-RANTester/internal/control_test_engine/gnb/context"

	ngap "github.com/free5gc/ngap/message"
	log "my5G-RANTester/internal/log"

	ngapType "github.com/free5gc/ngap/ie"
	ngapConvert "my5G-RANTester/lib/ngap"
)

type PathSwitchRequestBuilder struct {
	pdu *ngap.PathSwitchRequest
}

func PathSwitchRequest(gnb *context.GNBContext, ue *context.GNBUe) ([]byte, error) {
	return NewPathSwitchRequestBuilder().
		SetSourceAmfUeNgapId(ue.GetAmfUeId()).
		SetRanUeNgapId(ue.GetRanUeId()).
		PathSwitchRequestTransfer(gnb, ue.GetPduSessions()).
		SetUserLocation(gnb).
		SetUserSecurityCapabilities(ue.GetUESecurityCapabilities()).
		Build()
}

func NewPathSwitchRequestBuilder() *PathSwitchRequestBuilder {
	pdu := &ngap.PathSwitchRequest{}
	return &PathSwitchRequestBuilder{pdu}
}
func (builder *PathSwitchRequestBuilder) SetSourceAmfUeNgapId(amfUeNgapID int64) *PathSwitchRequestBuilder {
	builder.pdu.SourceAMFUENGAPID = &ngapType.AMFUENGAPID{Value: amfUeNgapID}
	return builder
}

func (builder *PathSwitchRequestBuilder) SetRanUeNgapId(ranUeNgapID int64) *PathSwitchRequestBuilder {
	builder.pdu.RANUENGAPID = &ngapType.RANUENGAPID{Value: ranUeNgapID}
	return builder
}

func (builder *PathSwitchRequestBuilder) SetUserLocation(gnb *context.GNBContext) *PathSwitchRequestBuilder {
	builder.pdu.UserLocationInformation = ngapConvert.UserLocation(gnb.GetPLMNIdentity(), gnb.GetNRCellIdentity(), gnb.GetTacInBytes())
	return builder
}

func (builder *PathSwitchRequestBuilder) SetUserSecurityCapabilities(userSecurityCapabilities *ngapType.UESecurityCapabilities) *PathSwitchRequestBuilder {
	builder.pdu.UESecurityCapabilities = userSecurityCapabilities
	return builder
}

// PathSwitchRequestTransfer signals the gNB's DL tunnel of each PDU session, at its N3
// address towards the session's UPF.
func (builder *PathSwitchRequestBuilder) PathSwitchRequestTransfer(gnb *context.GNBContext, pduSessions [16]*context.GnbPDUSession) *PathSwitchRequestBuilder {
	list := &ngapType.PDUSessionResourceToBeSwitchedDLList{}
	for _, session := range pduSessions {
		if session == nil {
			continue
		}
		transfer := &ngapType.PathSwitchRequestTransfer{
			DLNGUUPTNLInformation: ngapConvert.GTPTunnel(session.GetTeidDownlink(), gnb.GetDownlinkAddrs(session.GetUpfAddr())...),
			QosFlowAcceptedList:   &ngapType.QosFlowAcceptedList{List: []ngapType.QosFlowAcceptedItem{{QosFlowIdentifier: &ngapType.QosFlowIdentifier{Value: session.GetQosId()}}}},
		}
		encoded, err := ngapConvert.Marshal(transfer)
		if err != nil {
			log.Errorf("[GNB][NGAP] Unable to encode path switch transfer: %v", err)
			continue
		}
		list.List = append(list.List, ngapType.PDUSessionResourceToBeSwitchedDLItem{PDUSessionID: &ngapType.PDUSessionID{Value: session.GetPduSessionId()}, PathSwitchRequestTransfer: ngapConvert.Octets(encoded)})
	}
	if len(list.List) > 0 {
		builder.pdu.PDUSessionResourceToBeSwitchedDLList = list
	}
	return builder
}

func (builder *PathSwitchRequestBuilder) Build() ([]byte, error) {
	return builder.pdu.MarshalBinary()
}
