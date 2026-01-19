package chain

type Node struct {
	Name      string
	Addr      string
	transport Transporter
}

func NewNode(name, addr string, tr Transporter) *Node {
	return &Node{
		Name:      name,
		Addr:      addr,
		transport: tr,
	}
}

func (n *Node) Transport() Transporter {
	return n.transport
}
