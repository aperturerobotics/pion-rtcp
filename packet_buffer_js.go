// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build js

package rtcp

import "encoding/binary"

type packetBuffer struct {
	bytes []byte
}

func (b *packetBuffer) write(v any) error {
	switch v := v.(type) {
	case []byte:
		return b.writeBytes(v)
	case ExtendedReport:
		return b.writeExtendedReport(&v)
	case *ExtendedReport:
		return b.writeExtendedReport(v)
	case XRHeader:
		return b.writeXRHeader(&v)
	case *XRHeader:
		return b.writeXRHeader(v)
	case ReportBlock:
		return b.writeReportBlock(v)
	default:
		return errBadStructMemberType
	}
}

func (b *packetBuffer) writeExtendedReport(x *ExtendedReport) error {
	if x == nil {
		return errBadStructMemberType
	}
	if err := b.writeUint32(x.SenderSSRC); err != nil {
		return err
	}
	for _, p := range x.Reports {
		if err := b.writeReportBlock(p); err != nil {
			return err
		}
	}

	return nil
}

func (b *packetBuffer) writeReportBlock(p ReportBlock) error {
	switch p := p.(type) {
	case *LossRLEReportBlock:
		return b.writeRLEReportBlock(p.XRHeader, p.SSRC, p.BeginSeq, p.EndSeq, p.Chunks)
	case *DuplicateRLEReportBlock:
		return b.writeRLEReportBlock(p.XRHeader, p.SSRC, p.BeginSeq, p.EndSeq, p.Chunks)
	case *PacketReceiptTimesReportBlock:
		if err := b.writeXRHeader(&p.XRHeader); err != nil {
			return err
		}
		if err := b.writeUint32(p.SSRC); err != nil {
			return err
		}
		if err := b.writeUint16(p.BeginSeq); err != nil {
			return err
		}
		if err := b.writeUint16(p.EndSeq); err != nil {
			return err
		}
		for _, t := range p.ReceiptTime {
			if err := b.writeUint32(t); err != nil {
				return err
			}
		}

		return nil
	case *ReceiverReferenceTimeReportBlock:
		if err := b.writeXRHeader(&p.XRHeader); err != nil {
			return err
		}

		return b.writeUint64(p.NTPTimestamp)
	case *DLRRReportBlock:
		if err := b.writeXRHeader(&p.XRHeader); err != nil {
			return err
		}
		for _, report := range p.Reports {
			if err := b.writeUint32(report.SSRC); err != nil {
				return err
			}
			if err := b.writeUint32(report.LastRR); err != nil {
				return err
			}
			if err := b.writeUint32(report.DLRR); err != nil {
				return err
			}
		}

		return nil
	case *StatisticsSummaryReportBlock:
		if err := b.writeXRHeader(&p.XRHeader); err != nil {
			return err
		}
		if err := b.writeUint32(p.SSRC); err != nil {
			return err
		}
		if err := b.writeUint16(p.BeginSeq); err != nil {
			return err
		}
		if err := b.writeUint16(p.EndSeq); err != nil {
			return err
		}
		for _, v := range []uint32{p.LostPackets, p.DupPackets, p.MinJitter, p.MaxJitter, p.MeanJitter, p.DevJitter} {
			if err := b.writeUint32(v); err != nil {
				return err
			}
		}
		for _, v := range []uint8{p.MinTTLOrHL, p.MaxTTLOrHL, p.MeanTTLOrHL, p.DevTTLOrHL} {
			if err := b.writeUint8(v); err != nil {
				return err
			}
		}

		return nil
	case *VoIPMetricsReportBlock:
		if err := b.writeXRHeader(&p.XRHeader); err != nil {
			return err
		}
		if err := b.writeUint32(p.SSRC); err != nil {
			return err
		}
		for _, v := range []uint8{p.LossRate, p.DiscardRate, p.BurstDensity, p.GapDensity} {
			if err := b.writeUint8(v); err != nil {
				return err
			}
		}
		for _, v := range []uint16{p.BurstDuration, p.GapDuration, p.RoundTripDelay, p.EndSystemDelay} {
			if err := b.writeUint16(v); err != nil {
				return err
			}
		}
		for _, v := range []uint8{
			p.SignalLevel,
			p.NoiseLevel,
			p.RERL,
			p.Gmin,
			p.RFactor,
			p.ExtRFactor,
			p.MOSLQ,
			p.MOSCQ,
			p.RXConfig,
			0,
		} {
			if err := b.writeUint8(v); err != nil {
				return err
			}
		}
		for _, v := range []uint16{p.JBNominal, p.JBMaximum, p.JBAbsMax} {
			if err := b.writeUint16(v); err != nil {
				return err
			}
		}

		return nil
	case *UnknownReportBlock:
		if err := b.writeXRHeader(&p.XRHeader); err != nil {
			return err
		}

		return b.writeBytes(p.Bytes)
	default:
		return errBadStructMemberType
	}
}

func (b *packetBuffer) writeRLEReportBlock(h XRHeader, ssrc uint32, beginSeq uint16, endSeq uint16, chunks []Chunk) error {
	if err := b.writeXRHeader(&h); err != nil {
		return err
	}
	if err := b.writeUint32(ssrc); err != nil {
		return err
	}
	if err := b.writeUint16(beginSeq); err != nil {
		return err
	}
	if err := b.writeUint16(endSeq); err != nil {
		return err
	}
	for _, c := range chunks {
		if err := b.writeUint16(uint16(c)); err != nil {
			return err
		}
	}

	return nil
}

func (b *packetBuffer) writeXRHeader(h *XRHeader) error {
	if h == nil {
		return errBadStructMemberType
	}
	if err := b.writeUint8(uint8(h.BlockType)); err != nil {
		return err
	}
	if err := b.writeUint8(uint8(h.TypeSpecific)); err != nil {
		return err
	}

	return b.writeUint16(h.BlockLength)
}

func (b *packetBuffer) writeBytes(v []byte) error {
	if len(b.bytes) < len(v) {
		return errWrongMarshalSize
	}
	copy(b.bytes, v)
	b.bytes = b.bytes[len(v):]

	return nil
}

func (b *packetBuffer) writeUint8(v uint8) error {
	if len(b.bytes) < 1 {
		return errWrongMarshalSize
	}
	b.bytes[0] = v
	b.bytes = b.bytes[1:]

	return nil
}

func (b *packetBuffer) writeUint16(v uint16) error {
	if len(b.bytes) < 2 {
		return errWrongMarshalSize
	}
	binary.BigEndian.PutUint16(b.bytes, v)
	b.bytes = b.bytes[2:]

	return nil
}

func (b *packetBuffer) writeUint32(v uint32) error {
	if len(b.bytes) < 4 {
		return errWrongMarshalSize
	}
	binary.BigEndian.PutUint32(b.bytes, v)
	b.bytes = b.bytes[4:]

	return nil
}

func (b *packetBuffer) writeUint64(v uint64) error {
	if len(b.bytes) < 8 {
		return errWrongMarshalSize
	}
	binary.BigEndian.PutUint64(b.bytes, v)
	b.bytes = b.bytes[8:]

	return nil
}

func (b *packetBuffer) read(v any) error {
	switch v := v.(type) {
	case *uint32:
		return b.readUint32(v)
	case *XRHeader:
		return b.readXRHeader(v)
	case *LossRLEReportBlock:
		return b.readRLEReportBlock(&v.XRHeader, &v.SSRC, &v.BeginSeq, &v.EndSeq, &v.Chunks)
	case *DuplicateRLEReportBlock:
		return b.readRLEReportBlock(&v.XRHeader, &v.SSRC, &v.BeginSeq, &v.EndSeq, &v.Chunks)
	case *PacketReceiptTimesReportBlock:
		if err := b.readXRHeader(&v.XRHeader); err != nil {
			return err
		}
		if err := b.readUint32(&v.SSRC); err != nil {
			return err
		}
		if err := b.readUint16(&v.BeginSeq); err != nil {
			return err
		}
		if err := b.readUint16(&v.EndSeq); err != nil {
			return err
		}
		for len(b.bytes) > 0 {
			var receiptTime uint32
			if err := b.readUint32(&receiptTime); err != nil {
				return err
			}
			v.ReceiptTime = append(v.ReceiptTime, receiptTime)
		}

		return nil
	case *ReceiverReferenceTimeReportBlock:
		if err := b.readXRHeader(&v.XRHeader); err != nil {
			return err
		}

		return b.readUint64(&v.NTPTimestamp)
	case *DLRRReportBlock:
		if err := b.readXRHeader(&v.XRHeader); err != nil {
			return err
		}
		for len(b.bytes) > 0 {
			var report DLRRReport
			if err := b.readUint32(&report.SSRC); err != nil {
				return err
			}
			if err := b.readUint32(&report.LastRR); err != nil {
				return err
			}
			if err := b.readUint32(&report.DLRR); err != nil {
				return err
			}
			v.Reports = append(v.Reports, report)
		}

		return nil
	case *StatisticsSummaryReportBlock:
		if err := b.readXRHeader(&v.XRHeader); err != nil {
			return err
		}
		if err := b.readUint32(&v.SSRC); err != nil {
			return err
		}
		if err := b.readUint16(&v.BeginSeq); err != nil {
			return err
		}
		if err := b.readUint16(&v.EndSeq); err != nil {
			return err
		}
		for _, out := range []*uint32{
			&v.LostPackets,
			&v.DupPackets,
			&v.MinJitter,
			&v.MaxJitter,
			&v.MeanJitter,
			&v.DevJitter,
		} {
			if err := b.readUint32(out); err != nil {
				return err
			}
		}
		for _, out := range []*uint8{&v.MinTTLOrHL, &v.MaxTTLOrHL, &v.MeanTTLOrHL, &v.DevTTLOrHL} {
			if err := b.readUint8(out); err != nil {
				return err
			}
		}

		return nil
	case *VoIPMetricsReportBlock:
		if err := b.readXRHeader(&v.XRHeader); err != nil {
			return err
		}
		if err := b.readUint32(&v.SSRC); err != nil {
			return err
		}
		for _, out := range []*uint8{&v.LossRate, &v.DiscardRate, &v.BurstDensity, &v.GapDensity} {
			if err := b.readUint8(out); err != nil {
				return err
			}
		}
		for _, out := range []*uint16{&v.BurstDuration, &v.GapDuration, &v.RoundTripDelay, &v.EndSystemDelay} {
			if err := b.readUint16(out); err != nil {
				return err
			}
		}
		for _, out := range []*uint8{
			&v.SignalLevel,
			&v.NoiseLevel,
			&v.RERL,
			&v.Gmin,
			&v.RFactor,
			&v.ExtRFactor,
			&v.MOSLQ,
			&v.MOSCQ,
			&v.RXConfig,
		} {
			if err := b.readUint8(out); err != nil {
				return err
			}
		}
		var reserved uint8
		if err := b.readUint8(&reserved); err != nil {
			return err
		}
		for _, out := range []*uint16{&v.JBNominal, &v.JBMaximum, &v.JBAbsMax} {
			if err := b.readUint16(out); err != nil {
				return err
			}
		}

		return nil
	case *UnknownReportBlock:
		if err := b.readXRHeader(&v.XRHeader); err != nil {
			return err
		}
		v.Bytes = append(v.Bytes, b.bytes...)
		b.bytes = nil

		return nil
	default:
		return errBadReadParameter
	}
}

func (b *packetBuffer) readRLEReportBlock(h *XRHeader, ssrc *uint32, beginSeq *uint16, endSeq *uint16, chunks *[]Chunk) error {
	if err := b.readXRHeader(h); err != nil {
		return err
	}
	if err := b.readUint32(ssrc); err != nil {
		return err
	}
	if err := b.readUint16(beginSeq); err != nil {
		return err
	}
	if err := b.readUint16(endSeq); err != nil {
		return err
	}
	for len(b.bytes) > 0 {
		var chunk uint16
		if err := b.readUint16(&chunk); err != nil {
			return err
		}
		*chunks = append(*chunks, Chunk(chunk))
	}

	return nil
}

func (b *packetBuffer) readXRHeader(h *XRHeader) error {
	var blockType uint8
	if err := b.readUint8(&blockType); err != nil {
		return err
	}
	var typeSpecific uint8
	if err := b.readUint8(&typeSpecific); err != nil {
		return err
	}
	if err := b.readUint16(&h.BlockLength); err != nil {
		return err
	}
	h.BlockType = BlockTypeType(blockType)
	h.TypeSpecific = TypeSpecificField(typeSpecific)

	return nil
}

func (b *packetBuffer) readUint8(v *uint8) error {
	if len(b.bytes) < 1 {
		return errWrongMarshalSize
	}
	*v = b.bytes[0]
	b.bytes = b.bytes[1:]

	return nil
}

func (b *packetBuffer) readUint16(v *uint16) error {
	if len(b.bytes) < 2 {
		return errWrongMarshalSize
	}
	*v = binary.BigEndian.Uint16(b.bytes)
	b.bytes = b.bytes[2:]

	return nil
}

func (b *packetBuffer) readUint32(v *uint32) error {
	if len(b.bytes) < 4 {
		return errWrongMarshalSize
	}
	*v = binary.BigEndian.Uint32(b.bytes)
	b.bytes = b.bytes[4:]

	return nil
}

func (b *packetBuffer) readUint64(v *uint64) error {
	if len(b.bytes) < 8 {
		return errWrongMarshalSize
	}
	*v = binary.BigEndian.Uint64(b.bytes)
	b.bytes = b.bytes[8:]

	return nil
}

func (b *packetBuffer) split(size int) packetBuffer {
	if size > len(b.bytes) {
		size = len(b.bytes)
	}
	newBuffer := packetBuffer{bytes: b.bytes[:size]}
	b.bytes = b.bytes[size:]

	return newBuffer
}

func wireSize(v any) int {
	switch v := v.(type) {
	case ExtendedReport:
		return wireSizeExtendedReport(&v)
	case *ExtendedReport:
		return wireSizeExtendedReport(v)
	case XRHeader, *XRHeader:
		return 4
	case *LossRLEReportBlock:
		return wireSizeRLEReportBlock(v.Chunks)
	case *DuplicateRLEReportBlock:
		return wireSizeRLEReportBlock(v.Chunks)
	case *PacketReceiptTimesReportBlock:
		return 12 + len(v.ReceiptTime)*4
	case *ReceiverReferenceTimeReportBlock:
		return 12
	case *DLRRReportBlock:
		return 4 + len(v.Reports)*12
	case *StatisticsSummaryReportBlock:
		return 40
	case *VoIPMetricsReportBlock:
		return 36
	case *UnknownReportBlock:
		return 4 + len(v.Bytes)
	case DLRRReport:
		return 12
	case []byte:
		return len(v)
	default:
		return 0
	}
}

func wireSizeExtendedReport(x *ExtendedReport) int {
	if x == nil {
		return 0
	}
	size := 4
	for _, p := range x.Reports {
		size += wireSize(p)
	}

	return size
}

func wireSizeRLEReportBlock(chunks []Chunk) int {
	return 12 + len(chunks)*2
}
