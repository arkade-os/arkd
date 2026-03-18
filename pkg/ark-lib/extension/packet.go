package extension

type Packet interface {
	Type() uint8
	Serialize() ([]byte, error)
}

type UnknownPacket struct {
	PacketType uint8
	Data       []byte
}

func (p UnknownPacket) Type() uint8 {
	return p.PacketType
}

func (p UnknownPacket) Serialize() ([]byte, error) {
	return p.Data, nil
}
