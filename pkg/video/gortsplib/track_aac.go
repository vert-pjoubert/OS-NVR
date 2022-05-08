package gortsplib

import (
	"encoding/hex"
	"errors"
	"fmt"
	"nvr/pkg/video/gortsplib/pkg/aac"
	"strconv"
	"strings"

	psdp "github.com/pion/sdp/v3"
)

// AAC errors.
var (
	ErrAACfmtpMissing   = errors.New("fmtp attribute is missing")
	ErrACCfmtpInvalid   = errors.New("invalid fmtp")
	ErrACCconfigInvalid = errors.New("invalid AAC config")
	ErrACCconfigMissing = errors.New("config is missing")
)

// TrackAAC is an AAC track.
type TrackAAC struct {
	trackBase
	payloadType       uint8
	typ               int
	sampleRate        int
	channelCount      int
	aotSpecificConfig []byte
	mpegConf          []byte
}

// NewTrackAAC allocates a TrackAAC.
func NewTrackAAC(payloadType uint8, typ int, sampleRate int,
	channelCount int, aotSpecificConfig []byte,
) (*TrackAAC, error) {
	mpegConf, err := aac.MPEG4AudioConfig{
		Type:              aac.MPEG4AudioType(typ),
		SampleRate:        sampleRate,
		ChannelCount:      channelCount,
		AOTSpecificConfig: aotSpecificConfig,
	}.Encode()
	if err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &TrackAAC{
		payloadType:       payloadType,
		typ:               typ,
		sampleRate:        sampleRate,
		channelCount:      channelCount,
		aotSpecificConfig: aotSpecificConfig,
		mpegConf:          mpegConf,
	}, nil
}

func newTrackAACFromMediaDescription(
	control string,
	payloadType uint8,
	md *psdp.MediaDescription,
) (*TrackAAC, error) {
	v, ok := md.Attribute("fmtp")
	if !ok {
		return nil, ErrAACfmtpMissing
	}

	tmp := strings.SplitN(v, " ", 2)
	if len(tmp) != 2 {
		return nil, fmt.Errorf("%w (%v)", ErrACCfmtpInvalid, v)
	}

	for _, kv := range strings.Split(tmp[1], ";") {
		kv = strings.Trim(kv, " ")

		if len(kv) == 0 {
			continue
		}

		tmp := strings.SplitN(kv, "=", 2)
		if len(tmp) != 2 {
			return nil, fmt.Errorf("%w (%v)", ErrACCfmtpInvalid, v)
		}

		if tmp[0] == "config" {
			enc, err := hex.DecodeString(tmp[1])
			if err != nil {
				return nil, fmt.Errorf("%w (%v)", ErrACCconfigInvalid, tmp[1])
			}

			var mpegConf aac.MPEG4AudioConfig
			err = mpegConf.Decode(enc)
			if err != nil {
				return nil, fmt.Errorf("%w (%v)", ErrACCconfigInvalid, tmp[1])
			}

			// re-encode the conf to normalize it
			enc, _ = mpegConf.Encode()

			return &TrackAAC{
				trackBase: trackBase{
					control: control,
				},
				payloadType:       payloadType,
				typ:               int(mpegConf.Type),
				sampleRate:        mpegConf.SampleRate,
				channelCount:      mpegConf.ChannelCount,
				aotSpecificConfig: mpegConf.AOTSpecificConfig,
				mpegConf:          enc,
			}, nil
		}
	}

	return nil, fmt.Errorf("%w (%v)", ErrACCconfigMissing, v)
}

// ClockRate returns the track clock rate.
func (t *TrackAAC) ClockRate() int {
	return t.sampleRate
}

// Type returns the track MPEG4-audio type.
func (t *TrackAAC) Type() int {
	return t.typ
}

// ChannelCount returns the track channel count.
func (t *TrackAAC) ChannelCount() int {
	return t.channelCount
}

// AOTSpecificConfig returns the track AOT specific config.
func (t *TrackAAC) AOTSpecificConfig() []byte {
	return t.aotSpecificConfig
}

func (t *TrackAAC) clone() Track {
	return &TrackAAC{
		trackBase:         t.trackBase,
		payloadType:       t.payloadType,
		typ:               t.typ,
		sampleRate:        t.sampleRate,
		channelCount:      t.channelCount,
		aotSpecificConfig: t.aotSpecificConfig,
		mpegConf:          t.mpegConf,
	}
}

// MediaDescription returns the track media description in SDP format.
func (t *TrackAAC) MediaDescription() *psdp.MediaDescription {
	typ := strconv.FormatInt(int64(t.payloadType), 10)

	return &psdp.MediaDescription{
		MediaName: psdp.MediaName{
			Media:   "audio",
			Protos:  []string{"RTP", "AVP"},
			Formats: []string{typ},
		},
		Attributes: []psdp.Attribute{
			{
				Key: "rtpmap",
				Value: typ + " mpeg4-generic/" + strconv.FormatInt(int64(t.sampleRate), 10) +
					"/" + strconv.FormatInt(int64(t.channelCount), 10),
			},
			{
				Key: "fmtp",
				Value: typ + " profile-level-id=1; " +
					"mode=AAC-hbr; " +
					"sizelength=13; " +
					"indexlength=3; " +
					"indexdeltalength=3; " +
					"config=" + hex.EncodeToString(t.mpegConf),
			},
			{
				Key:   "control",
				Value: t.control,
			},
		},
	}
}