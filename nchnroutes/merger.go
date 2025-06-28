package nchnroutes

import (
	"net"
	"sort"
)

// CIDR represents a network range for merging
type CIDR struct {
	Network *net.IPNet
	StartIP net.IP
	EndIP   net.IP
}

// RangesToCIDRs 将IP范围转换为CIDR进行合并
func RangesToCIDRs(ranges []IPRange) []CIDR {
	var cidrs []CIDR

	for _, r := range ranges {
		_, network, err := net.ParseCIDR(r.CIDR)
		if err != nil {
			continue
		}

		cidr := CIDR{
			Network: network,
			StartIP: r.StartIP,
			EndIP:   r.EndIP,
		}
		cidrs = append(cidrs, cidr)
	}

	return cidrs
}

// MergeCIDRs 合并相邻的CIDR
func MergeCIDRs(cidrs []CIDR) []CIDR {
	if len(cidrs) == 0 {
		return cidrs
	}

	// 按起始IP排序
	sort.Slice(cidrs, func(i, j int) bool {
		return compareIPs(cidrs[i].StartIP, cidrs[j].StartIP) < 0
	})

	var merged []CIDR
	current := cidrs[0]

	for i := 1; i < len(cidrs); i++ {
		next := cidrs[i]

		// 检查是否可以合并（真正相邻的网段）
		if isAdjacent(current, next) {
			// 尝试合并
			if mergedCIDR := tryMergeAdjacent(current, next); mergedCIDR != nil {
				current = *mergedCIDR
			} else {
				merged = append(merged, current)
				current = next
			}
		} else if overlaps(current, next) {
			// 处理重叠的情况
			current = mergeOverlapping(current, next)
		} else {
			merged = append(merged, current)
			current = next
		}
	}

	merged = append(merged, current)
	return merged
}

// compareIPs 比较两个IP地址
func compareIPs(ip1, ip2 net.IP) int {
	// 确保两个IP长度相同
	if len(ip1) != len(ip2) {
		ip1 = ip1.To16()
		ip2 = ip2.To16()
	}

	for i := 0; i < len(ip1); i++ {
		if ip1[i] < ip2[i] {
			return -1
		} else if ip1[i] > ip2[i] {
			return 1
		}
	}
	return 0
}

// isAdjacent 检查两个CIDR是否相邻
func isAdjacent(cidr1, cidr2 CIDR) bool {
	// 检查IP版本是否相同
	if (cidr1.StartIP.To4() != nil) != (cidr2.StartIP.To4() != nil) {
		return false
	}

	// 检查第一个的结束IP + 1 是否等于第二个的开始IP
	return isNextIP(cidr1.EndIP, cidr2.StartIP)
}

// overlaps 检查两个CIDR是否重叠
func overlaps(cidr1, cidr2 CIDR) bool {
	// 检查IP版本是否相同
	if (cidr1.StartIP.To4() != nil) != (cidr2.StartIP.To4() != nil) {
		return false
	}

	// 检查是否有重叠
	return compareIPs(cidr1.StartIP, cidr2.EndIP) <= 0 &&
		compareIPs(cidr2.StartIP, cidr1.EndIP) <= 0
}

// isNextIP 检查ip1 + 1 是否等于 ip2
func isNextIP(ip1, ip2 net.IP) bool {
	nextIP := make(net.IP, len(ip1))
	copy(nextIP, ip1)

	// 对IP地址加1
	for i := len(nextIP) - 1; i >= 0; i-- {
		nextIP[i]++
		if nextIP[i] != 0 {
			break
		}
	}

	return nextIP.Equal(ip2)
}

// tryMergeAdjacent 尝试合并相邻的CIDR
func tryMergeAdjacent(cidr1, cidr2 CIDR) *CIDR {
	// 只有当两个CIDR的前缀长度相同且可以合并成更大的CIDR时才合并
	prefix1, _ := cidr1.Network.Mask.Size()
	prefix2, _ := cidr2.Network.Mask.Size()

	if prefix1 != prefix2 || prefix1 == 0 {
		return nil
	}

	// 检查是否可以合并成更大的网络
	newPrefix := prefix1 - 1
	var bits int
	if cidr1.StartIP.To4() != nil {
		bits = 32
	} else {
		bits = 128
	}

	if newPrefix < 0 {
		return nil
	}

	mask := net.CIDRMask(newPrefix, bits)
	network1 := &net.IPNet{IP: cidr1.StartIP.Mask(mask), Mask: mask}
	network2 := &net.IPNet{IP: cidr2.StartIP.Mask(mask), Mask: mask}

	// 如果两个网络在新的前缀下是同一个网络，则可以合并
	if network1.IP.Equal(network2.IP) {
		startIP := cidr1.StartIP
		if compareIPs(cidr2.StartIP, startIP) < 0 {
			startIP = cidr2.StartIP
		}

		endIP := cidr1.EndIP
		if compareIPs(cidr2.EndIP, endIP) > 0 {
			endIP = cidr2.EndIP
		}

		return &CIDR{
			Network: network1,
			StartIP: startIP,
			EndIP:   endIP,
		}
	}

	return nil
}

// mergeOverlapping 合并重叠的CIDR
func mergeOverlapping(cidr1, cidr2 CIDR) CIDR {
	startIP := cidr1.StartIP
	if compareIPs(cidr2.StartIP, startIP) < 0 {
		startIP = cidr2.StartIP
	}

	endIP := cidr1.EndIP
	if compareIPs(cidr2.EndIP, endIP) > 0 {
		endIP = cidr2.EndIP
	}

	// 计算包含整个范围的最小网络
	network := calculateMinimalNetwork(startIP, endIP)

	return CIDR{
		Network: network,
		StartIP: startIP,
		EndIP:   endIP,
	}
}

// calculateMinimalNetwork 计算包含指定范围的最小网络
func calculateMinimalNetwork(startIP, endIP net.IP) *net.IPNet {
	isIPv4 := startIP.To4() != nil
	var bits int
	if isIPv4 {
		bits = 32
	} else {
		bits = 128
	}

	// 找到能包含整个范围的最小前缀
	for prefix := bits; prefix >= 0; prefix-- {
		mask := net.CIDRMask(prefix, bits)
		network := &net.IPNet{IP: startIP.Mask(mask), Mask: mask}

		if network.Contains(startIP) && network.Contains(endIP) {
			return network
		}
	}

	// 默认返回最大范围（应该不会到达这里）
	if isIPv4 {
		return &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
	}
	return &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
}
