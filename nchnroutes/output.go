package nchnroutes

import (
	"fmt"
	"os"
	"strings"
)

// OutputIPv4BirdConfig 输出IPv4 Bird配置
func OutputIPv4BirdConfig(ipv4CIDRs []CIDR, outputFile string) error {
	var content strings.Builder

	content.WriteString("# Bird IPv4配置文件 - 非中国大陆IP段（排除私有地址）\n")
	content.WriteString("# 生成时间: " + fmt.Sprintf("%v", os.Getenv("USER")) + "\n\n")

	if len(ipv4CIDRs) > 0 {
		content.WriteString("# IPv4路由表\n")
		content.WriteString("define NON_CN_IPV4 = [\n")

		for i, cidr := range ipv4CIDRs {
			if i == len(ipv4CIDRs)-1 {
				content.WriteString(fmt.Sprintf("    %s\n", cidr.Network.String()))
			} else {
				content.WriteString(fmt.Sprintf("    %s,\n", cidr.Network.String()))
			}
		}
		content.WriteString("];\n\n")

		// 添加使用示例
		content.WriteString("# 使用示例:\n")
		content.WriteString("# filter non_cn_ipv4_filter {\n")
		content.WriteString("#     if net ~ NON_CN_IPV4 then accept;\n")
		content.WriteString("#     reject;\n")
		content.WriteString("# }\n")
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
func OutputIPv6BirdConfig(ipv6CIDRs []CIDR, outputFile string) error {
	var content strings.Builder

	content.WriteString("# Bird IPv6配置文件 - 非中国大陆IP段（排除私有地址）\n")
	content.WriteString("# 生成时间: " + fmt.Sprintf("%v", os.Getenv("USER")) + "\n\n")

	if len(ipv6CIDRs) > 0 {
		content.WriteString("# IPv6路由表\n")
		content.WriteString("define NON_CN_IPV6 = [\n")

		for i, cidr := range ipv6CIDRs {
			if i == len(ipv6CIDRs)-1 {
				content.WriteString(fmt.Sprintf("    %s\n", cidr.Network.String()))
			} else {
				content.WriteString(fmt.Sprintf("    %s,\n", cidr.Network.String()))
			}
		}
		content.WriteString("];\n\n")

		// 添加使用示例
		content.WriteString("# 使用示例:\n")
		content.WriteString("# filter non_cn_ipv6_filter {\n")
		content.WriteString("#     if net ~ NON_CN_IPV6 then accept;\n")
		content.WriteString("#     reject;\n")
		content.WriteString("# }\n")
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
