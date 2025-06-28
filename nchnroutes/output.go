package nchnroutes

import (
	"fmt"
	"os"
	"strings"
)

// OutputIPv4BirdConfig 输出IPv4 Bird配置
func OutputIPv4BirdConfig(ipv4CIDRs []CIDR, outputFile string, iface string) error {
	var content strings.Builder

	content.WriteString("# Bird IPv4路由配置文件 - 非中国大陆IP段（排除私有地址）\n")
	content.WriteString("# 生成时间: " + fmt.Sprintf("%v", os.Getenv("USER")) + "\n\n")

	if len(ipv4CIDRs) > 0 {
		content.WriteString("# IPv4路由表\n")
		for _, cidr := range ipv4CIDRs {
			content.WriteString(fmt.Sprintf("route %s via \"%s\";\n", cidr.Network.String(), iface))
		}
		content.WriteString("\n")

		// 添加使用说明
		content.WriteString("# 使用说明:\n")
		content.WriteString("# 将以上路由配置添加到Bird配置文件中\n")
		content.WriteString(fmt.Sprintf("# 当前使用接口: %s\n", iface))
	} else {
		content.WriteString("# 没有IPv4数据\n")
	}

	if outputFile == "" {
		fmt.Print(content.String())
	} else {
		err := os.WriteFile(outputFile, []byte(content.String()), 0644)
		if err != nil {
			return err
		}
		fmt.Printf("IPv4配置已保存到: %s\n", outputFile)
	}

	return nil
}

// OutputIPv6BirdConfig 输出IPv6 Bird配置
func OutputIPv6BirdConfig(ipv6CIDRs []CIDR, outputFile string, iface string) error {
	var content strings.Builder

	content.WriteString("# Bird IPv6路由配置文件 - 非中国大陆IP段（排除私有地址）\n")
	content.WriteString("# 生成时间: " + fmt.Sprintf("%v", os.Getenv("USER")) + "\n\n")

	if len(ipv6CIDRs) > 0 {
		content.WriteString("# IPv6路由表\n")
		for _, cidr := range ipv6CIDRs {
			content.WriteString(fmt.Sprintf("route %s via \"%s\";\n", cidr.Network.String(), iface))
		}
		content.WriteString("\n")

		// 添加使用说明
		content.WriteString("# 使用说明:\n")
		content.WriteString("# 将以上路由配置添加到Bird配置文件中\n")
		content.WriteString(fmt.Sprintf("# 当前使用接口: %s\n", iface))
	} else {
		content.WriteString("# 没有IPv6数据\n")
	}

	if outputFile == "" {
		fmt.Print(content.String())
	} else {
		err := os.WriteFile(outputFile, []byte(content.String()), 0644)
		if err != nil {
			return err
		}
		fmt.Printf("IPv6配置已保存到: %s\n", outputFile)
	}

	return nil
}
