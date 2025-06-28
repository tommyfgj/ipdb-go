package nchnroutes

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

// MetaData IPDB元数据结构
type MetaData struct {
	Build     int64          `json:"build"`
	IPVersion uint16         `json:"ip_version"`
	Languages map[string]int `json:"languages"`
	NodeCount int            `json:"node_count"`
	TotalSize int            `json:"total_size"`
	Fields    []string       `json:"fields"`
}

// IPDBExtractor IPDB提取器
type IPDBExtractor struct {
	data      []byte
	nodeCount int
	v4offset  int
	meta      MetaData
}

// IPRange IP范围结构
type IPRange struct {
	CIDR    string
	StartIP net.IP
	EndIP   net.IP
	Info    []string
	RawData string
	Type    string // "IPv4" or "IPv6"
}

// NewExtractor 创建新的IPDB提取器
func NewExtractor(filename string) (*IPDBExtractor, error) {
	body, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	metaLength := int(binary.BigEndian.Uint32(body[0:4]))
	var meta MetaData
	if err := json.Unmarshal(body[4:4+metaLength], &meta); err != nil {
		return nil, err
	}

	extractor := &IPDBExtractor{
		data:      body[4+metaLength:],
		nodeCount: meta.NodeCount,
		meta:      meta,
	}

	extractor.calculateV4Offset()
	return extractor, nil
}

// GetMeta 获取元数据
func (e *IPDBExtractor) GetMeta() MetaData {
	return e.meta
}

func (e *IPDBExtractor) calculateV4Offset() {
	node := 0
	for i := 0; i < 96 && node < e.nodeCount; i++ {
		if i >= 80 {
			node = e.readNode(node, 1)
		} else {
			node = e.readNode(node, 0)
		}
	}
	e.v4offset = node
}

func (e *IPDBExtractor) readNode(node, index int) int {
	off := node*8 + index*4
	return int(binary.BigEndian.Uint32(e.data[off : off+4]))
}

func (e *IPDBExtractor) resolve(node int) ([]byte, error) {
	resolved := node - e.nodeCount + e.nodeCount*8
	if resolved >= len(e.data) {
		return nil, fmt.Errorf("database error")
	}

	size := int(binary.BigEndian.Uint16(e.data[resolved : resolved+2]))
	if (resolved + 2 + size) > len(e.data) {
		return nil, fmt.Errorf("database error")
	}
	bytes := e.data[resolved+2 : resolved+2+size]

	return bytes, nil
}

// ExtractAllRanges 提取所有IP范围（IPv4和IPv6）
func (e *IPDBExtractor) ExtractAllRanges() ([]IPRange, []IPRange, error) {
	var ipv4Ranges, ipv6Ranges []IPRange

	if (e.meta.IPVersion & 0x01) != 0 {
		e.traverseIPv4Node(e.v4offset, make([]int, 0, 32), &ipv4Ranges)
	}

	if (e.meta.IPVersion & 0x02) != 0 {
		e.traverseIPv6NodeFromRoot(0, make([]int, 0, 128), &ipv6Ranges)
	}

	return ipv4Ranges, ipv6Ranges, nil
}

func (e *IPDBExtractor) traverseIPv4Node(node int, path []int, ranges *[]IPRange) {
	if node >= e.nodeCount {
		data, err := e.resolve(node)
		if err != nil {
			return
		}

		cidr, startIP, endIP := e.pathToCIDR(path, true)
		str := string(data)
		info := strings.Split(str, "\t")

		ipRange := IPRange{
			CIDR:    cidr,
			StartIP: startIP,
			EndIP:   endIP,
			Info:    info,
			RawData: str,
			Type:    "IPv4",
		}

		*ranges = append(*ranges, ipRange)
		return
	}

	leftNode := e.readNode(node, 0)
	rightNode := e.readNode(node, 1)

	if leftNode != 0 {
		newPath := append(path, 0)
		e.traverseIPv4Node(leftNode, newPath, ranges)
	}

	if rightNode != 0 {
		newPath := append(path, 1)
		e.traverseIPv4Node(rightNode, newPath, ranges)
	}
}

func (e *IPDBExtractor) traverseIPv6NodeFromRoot(node int, path []int, ranges *[]IPRange) {
	if len(path) == 96 && e.isIPv4MappedPath(path) {
		return
	}

	if len(path) < 80 {
		allZeros := true
		for _, bit := range path {
			if bit != 0 {
				allZeros = false
				break
			}
		}
		if allZeros && len(path) >= 70 {
		}
	}

	if node >= e.nodeCount {
		if !e.isIPv4MappedPath(path) {
			data, err := e.resolve(node)
			if err != nil {
				return
			}

			cidr, startIP, endIP := e.pathToCIDR(path, false)
			str := string(data)
			info := strings.Split(str, "\t")

			ipRange := IPRange{
				CIDR:    cidr,
				StartIP: startIP,
				EndIP:   endIP,
				Info:    info,
				RawData: str,
				Type:    "IPv6",
			}

			*ranges = append(*ranges, ipRange)
		}
		return
	}

	leftNode := e.readNode(node, 0)
	rightNode := e.readNode(node, 1)

	if leftNode != 0 {
		newPath := append(path, 0)
		e.traverseIPv6NodeFromRoot(leftNode, newPath, ranges)
	}

	if rightNode != 0 {
		newPath := append(path, 1)
		e.traverseIPv6NodeFromRoot(rightNode, newPath, ranges)
	}
}

func (e *IPDBExtractor) isIPv4MappedPath(path []int) bool {
	if len(path) < 96 {
		return false
	}

	for i := 0; i < 80; i++ {
		if path[i] != 0 {
			return false
		}
	}

	for i := 80; i < 96; i++ {
		if path[i] != 1 {
			return false
		}
	}

	return true
}

func (e *IPDBExtractor) pathToCIDR(path []int, isIPv4 bool) (string, net.IP, net.IP) {
	var ip net.IP
	var prefixLen int

	if isIPv4 {
		ip = make(net.IP, 4)
		prefixLen = len(path)

		for i, bit := range path {
			if bit == 1 {
				byteIndex := i / 8
				bitIndex := 7 - (i % 8)
				ip[byteIndex] |= 1 << bitIndex
			}
		}
	} else {
		ip = make(net.IP, 16)
		prefixLen = len(path)

		for i, bit := range path {
			if bit == 1 {
				byteIndex := i / 8
				bitIndex := 7 - (i % 8)
				ip[byteIndex] |= 1 << bitIndex
			}
		}
	}

	cidr := fmt.Sprintf("%s/%d", ip.String(), prefixLen)
	startIP := make(net.IP, len(ip))
	copy(startIP, ip)
	endIP := e.calculateEndIP(ip, prefixLen, isIPv4)

	return cidr, startIP, endIP
}

func (e *IPDBExtractor) calculateEndIP(startIP net.IP, prefixLen int, isIPv4 bool) net.IP {
	var totalBits int
	if isIPv4 {
		totalBits = 32
	} else {
		totalBits = 128
	}

	hostBits := totalBits - prefixLen
	if hostBits == 0 {
		endIP := make(net.IP, len(startIP))
		copy(endIP, startIP)
		return endIP
	}

	endIP := make(net.IP, len(startIP))
	copy(endIP, startIP)

	for i := prefixLen; i < totalBits; i++ {
		byteIndex := i / 8
		bitIndex := 7 - (i % 8)
		endIP[byteIndex] |= 1 << bitIndex
	}

	return endIP
}
