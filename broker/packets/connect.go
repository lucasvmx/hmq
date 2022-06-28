/*
 * Copyright (c) 2021 IBM Corp and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    https://www.eclipse.org/legal/epl-2.0/
 * and the Eclipse Distribution License is available at
 *   http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    Allan Stockdill-Mander
 */

package packets

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
)

type ConnectProperty struct {
	// Used in MQTT v5
	PropertiesLen      byte
	SessExpInterval    uint32
	ReceiveMaximum     uint16
	MaxPacketSize      uint32
	TopicAliasMax      uint16
	RequestRespInfo    byte
	RequestProblemInfo byte
	UserProperties     []string
	AuthMethod         string
	AuthData           []byte

	// Control flags
	bHasSessExp        bool
	bHasRecvMax        bool
	bHasTopicAliasMax  bool
	bHasReqRespInfo    bool
	bHasReqProblemInfo bool
	bHasAuthMethod     bool
	bHasAuthData       bool
}

// ConnectPacket is an internal representation of the fields of the
// Connect MQTT packet
type ConnectPacket struct {
	FixedHeader
	ProtocolName    string
	ProtocolVersion byte
	CleanSession    bool
	WillFlag        bool
	WillQos         byte
	WillRetain      bool
	UsernameFlag    bool
	PasswordFlag    bool
	ReservedBit     byte
	Keepalive       uint16

	ClientIdentifier string
	WillTopic        string
	WillMessage      []byte
	Username         string
	Password         []byte

	property *ConnectProperty
}

// ID's of User Properties
var (
	UserPropertyIds = map[string]int{

		// CONNECT properties
		"SessionExpiryIntervalId":      0x11,
		"ReceiveMaximumId":             0x21,
		"MaximumPacketSizeId":          0x27,
		"TopicAliasMaximumId":          0x22,
		"RequestResponseInformationId": 0x19,
		"RequestProblemInformationId":  0x17,
		"UserPropertyId":               0x26,
		"AuthenticationMethodId":       0x15,
		"AuthenticationDataId":         0x16,

		// CONNECT payloads
	}
)

func (c *ConnectPacket) String() string {

	var psw string
	if len(c.Password) > 0 {
		psw = "<redacted>"
	}
	return fmt.Sprintf("%s protocolversion: %d protocolname: %s cleansession: %t willflag: %t WillQos: %d WillRetain: %t Usernameflag: %t Passwordflag: %t keepalive: %d clientId: %s willtopic: %s willmessage: %s Username: %s Password: %s", c.FixedHeader, c.ProtocolVersion, c.ProtocolName, c.CleanSession, c.WillFlag, c.WillQos, c.WillRetain, c.UsernameFlag, c.PasswordFlag, c.Keepalive, c.ClientIdentifier, c.WillTopic, c.WillMessage, c.Username, psw)
}

func (c *ConnectPacket) Write(w io.Writer) error {
	var body bytes.Buffer
	var err error

	body.Write(encodeString(c.ProtocolName))
	body.WriteByte(c.ProtocolVersion)
	body.WriteByte(boolToByte(c.CleanSession)<<1 | boolToByte(c.WillFlag)<<2 | c.WillQos<<3 | boolToByte(c.WillRetain)<<5 | boolToByte(c.PasswordFlag)<<6 | boolToByte(c.UsernameFlag)<<7)
	body.Write(encodeUint16(c.Keepalive))
	body.Write(encodeString(c.ClientIdentifier))
	if c.WillFlag {
		body.Write(encodeString(c.WillTopic))
		body.Write(encodeBytes(c.WillMessage))
	}
	if c.UsernameFlag {
		body.Write(encodeString(c.Username))
	}
	if c.PasswordFlag {
		body.Write(encodeBytes(c.Password))
	}
	c.FixedHeader.RemainingLength = body.Len()
	packet := c.FixedHeader.pack()
	packet.Write(body.Bytes())
	_, err = packet.WriteTo(w)

	return err
}

// Unpack decodes the details of a ControlPacket after the fixed
// header has been read
func (c *ConnectPacket) Unpack(b io.Reader) error {
	var err error
	c.ProtocolName, err = decodeString(b)
	if err != nil {
		return err
	}
	c.ProtocolVersion, err = decodeByte(b)
	if err != nil {
		return err
	}
	flags, err := decodeByte(b)
	if err != nil {
		return err
	}
	c.ReservedBit = 1 & flags
	c.CleanSession = 1&(flags>>1) > 0
	c.WillFlag = 1&(flags>>2) > 0
	c.WillQos = 3 & (flags >> 3)
	c.WillRetain = 1&(flags>>5) > 0
	c.PasswordFlag = 1&(flags>>6) > 0
	c.UsernameFlag = 1&(flags>>7) > 0
	c.Keepalive, err = decodeUint16(b)
	if err != nil {
		return err
	}
	c.ClientIdentifier, err = decodeString(b)
	if err != nil {
		return err
	}
	if c.WillFlag {
		c.WillTopic, err = decodeString(b)
		if err != nil {
			return err
		}
		c.WillMessage, err = decodeBytes(b)
		if err != nil {
			return err
		}
	}
	if c.UsernameFlag {
		c.Username, err = decodeString(b)
		if err != nil {
			return err
		}
	}
	if c.PasswordFlag {
		c.Password, err = decodeBytes(b)
		if err != nil {
			return err
		}
	}

	return nil
}

func (cp *ConnectPacket) getNextFieldType(b io.Reader) int {

	data, fail := decodeByte(b)
	if fail != nil {
		return 0
	}

	return int(data)
}

func (c *ConnectPacket) UnpackV5(b io.Reader) error {

	err := c.Unpack(b)
	if err != nil {
		return err
	}

	// Setup default property values
	c.property.SessExpInterval = 0
	c.property.TopicAliasMax = 0
	c.property.RequestRespInfo = 1
	c.property.RequestProblemInfo = 1

	// Unpack CONNECT properties
	err = c.UnpackProperties(b)
	if err != nil {
		return err
	}

	return nil
}

// UnpackProperties decodes the details of a ControlPacket after the fixed
// header has been read (MQTT V5)
func (c *ConnectPacket) UnpackProperties(b io.Reader) error {

	var err error
	var remainingLen byte

	c.property.PropertiesLen, err = decodeByte(b)
	if err != nil {
		return err
	}

	// set remaining length
	remainingLen = c.property.PropertiesLen

	// field decoding loop
	for remainingLen < c.property.PropertiesLen {

		fieldType := c.getNextFieldType(b)

		switch fieldType {
		case UserPropertyIds["SessionExpiryIntervalId"]:

			// This field can't be defined more than once
			if c.property.bHasSessExp {
				return ErrorProtocolViolation
			}

			c.property.SessExpInterval, err = decodeUint32(b)
			if err != nil {
				return err
			}

			remainingLen -= byte(reflect.TypeOf(c.property.SessExpInterval).Size())

			break
		case UserPropertyIds["ReceiveMaximumId"]:

			// This field can't be defined more than once
			if c.property.bHasRecvMax {
				return ErrorProtocolViolation
			}

			c.property.ReceiveMaximum, err = decodeUint16(b)
			if err != nil {
				return err
			}

			remainingLen -= byte(reflect.TypeOf(c.property.ReceiveMaximum).Size())

			break
		case UserPropertyIds["MaximumPacketSizeId"]:
			c.property.MaxPacketSize, err = decodeUint32(b)
			if err != nil {
				return err
			}

			remainingLen -= byte(reflect.TypeOf(c.property.MaxPacketSize).Size())
			break
		case UserPropertyIds["TopicAliasMaximumId"]:
			if c.property.bHasTopicAliasMax {
				return ErrorProtocolViolation
			}

			c.property.TopicAliasMax, err = decodeUint16(b)
			if err != nil {
				return err
			}

			remainingLen -= byte(reflect.TypeOf(c.property.TopicAliasMax).Size())
			break
		case UserPropertyIds["RequestResponseInformationId"]:
			if c.property.bHasReqRespInfo {
				return ErrorProtocolViolation
			}

			c.property.RequestRespInfo, err = decodeByte(b)
			if err != nil {
				return err
			}

			remainingLen -= byte(reflect.TypeOf(c.property.RequestRespInfo).Size())

			break
		case UserPropertyIds["RequestProblemInformationId"]:
			if c.property.bHasReqProblemInfo {
				return ErrorProtocolViolation
			}

			c.property.RequestProblemInfo, err = decodeByte(b)
			if err != nil {
				return err
			}

			remainingLen -= byte(reflect.TypeOf(c.property.RequestProblemInfo).Size())
			break
		case UserPropertyIds["UserPropertyId"]:

			field, err := decodeString(b)
			if err != nil {
				return err
			}

			c.property.UserProperties = append(c.property.UserProperties, field)

			break
		case UserPropertyIds["AuthenticationMethodId"]:

			c.property.AuthMethod, err = decodeString(b)
			if err != nil {
				return err
			}

			remainingLen -= byte(len(c.property.AuthMethod))

			break
		case UserPropertyIds["AuthenticationDataId"]:
			if !c.property.bHasAuthMethod || c.property.bHasAuthData {
				return ErrorProtocolViolation
			}

			c.property.AuthData, err = decodeBytes(b)
			if err != nil {
				return err
			}

			remainingLen -= byte(len(c.property.AuthData))

			break
		}
	}

	return nil
}

// Validate performs validation of the fields of a Connect packet
func (c *ConnectPacket) Validate(v5 bool) byte {
	if c.PasswordFlag && !c.UsernameFlag {
		return ErrRefusedBadUsernameOrPassword
	}
	if c.ReservedBit != 0 {
		// Bad reserved bit
		return ErrProtocolViolation
	}

	if v5 && (c.ProtocolName != "MQTT" || c.ProtocolVersion != 5) {
		// Mismatched or unsupported protocol version
		return ErrRefusedBadProtocolVersion
	} else if (c.ProtocolName == "MQIsdp" && c.ProtocolVersion != 3) ||
		(c.ProtocolName == "MQTT" && c.ProtocolVersion != 4) {
		// Mismatched or unsupported protocol version
		return ErrRefusedBadProtocolVersion
	}

	if v5 {
		if c.property.MaxPacketSize == 0 || c.property.ReceiveMaximum == 0 {
			return ErrProtocolViolation
		}
	}

	if c.ProtocolName != "MQIsdp" && c.ProtocolName != "MQTT" {
		// Bad protocol name
		return ErrProtocolViolation
	}

	if len(c.ClientIdentifier) > 65535 || len(c.Username) > 65535 || len(c.Password) > 65535 {
		// Bad size field
		return ErrProtocolViolation
	}
	if len(c.ClientIdentifier) == 0 && !c.CleanSession {
		// Bad client identifier
		return ErrRefusedIDRejected
	}

	return Accepted
}

// Details returns a Details struct containing the Qos and
// MessageID of this ControlPacket
func (c *ConnectPacket) Details() Details {
	return Details{Qos: 0, MessageID: 0}
}

func (c *ConnectPacket) GetStringFields() (fields []string) {

	fields = append(fields, c.ClientIdentifier)
	fields = append(fields, c.ProtocolName)
	fields = append(fields, c.Username)
	fields = append(fields, c.WillTopic)
	fields = append(fields, string(c.Password))
	fields = append(fields, string(c.WillMessage))

	return
}
