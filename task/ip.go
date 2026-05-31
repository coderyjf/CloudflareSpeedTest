package task

import (
	"bufio"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"
)

const defaultInputFile = "ip.txt"

var (
	// IPFile is the filename of IP Rangs
	IPFile = defaultInputFile
	IPText string
	Mask   = 54
)

func InitRandSeed() {
	rand.Seed(time.Now().UnixNano())
}

func isIPv4(ip string) bool {
	return strings.Contains(ip, ".")
}

func randIPEndWith(num int) byte {
	if num == 0 { // 对于 /32 这种单独的 IP
		return byte(0)
	}
	return byte(rand.Intn(num))
}

type IPRanges struct {
	ips     []*net.IPAddr
	mask    string
	firstIP net.IP
	ipNet   *net.IPNet
}

func newIPRanges() *IPRanges {
	return &IPRanges{
		ips: make([]*net.IPAddr, 0),
	}
}

func incrementIP(ip net.IP, start, end int) {
	for i := start; i >= end; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}

func calcMaskValues(mask int) (byteIndex int, bitOffset int, fixedMask byte, randomMask byte, step byte) {
	byteIndex = mask / 8
	bitOffset = mask % 8
	if byteIndex >= 16 {
		byteIndex = 15
		bitOffset = 8
	}
	if bitOffset == 0 {
		byteIndex -= 1
		fixedMask = 0xFF
		randomMask = 0x00
		step = 0x01
		return
	}
	fixedMask = byte(0xFF << (8 - bitOffset))
	randomMask = ^fixedMask
	step = byte(0x01 << (8 - bitOffset))
	return
}

// 如果是单独 IP 则加上子网掩码，反之则获取子网掩码(r.mask)
func (r *IPRanges) fixIP(ip string) string {
	// 如果不含有 '/' 则代表不是 IP 段，而是一个单独的 IP，因此需要加上 /32 /128 子网掩码
	if i := strings.IndexByte(ip, '/'); i < 0 {
		if isIPv4(ip) {
			r.mask = "/32"
		} else {
			r.mask = "/128"
		}
		ip += r.mask
	} else {
		r.mask = ip[i:]
	}
	return ip
}

// 解析 IP 段，获得 IP、IP 范围、子网掩码
func (r *IPRanges) parseCIDR(ip string) {
	var err error
	if r.firstIP, r.ipNet, err = net.ParseCIDR(r.fixIP(ip)); err != nil {
		log.Fatalln("ParseCIDR err", err)
	}
}

func (r *IPRanges) appendIP(ip net.IP) {
	r.ips = append(r.ips, &net.IPAddr{IP: ip})
}

func (r *IPRanges) chooseIPv4() {
	if Mask > 32 || Mask <= 0 {
		Mask = 24
	}
	if r.mask == "/32" { // 单个 IP 则无需随机，直接加入自身即可
		r.appendIP(r.firstIP)
	} else {
		byteIndex, _, fixedMask, randomMask, step := calcMaskValues(Mask)
		byteIndex += 12
		for r.ipNet.Contains(r.firstIP) { // 只要该 IP 没有超出 IP 网段范围，就继续循环随机
			ip := make(net.IP, len(r.firstIP))
			copy(ip, r.firstIP)
			for i := byteIndex; i < 16; i++ {
				ip[i] = randIPEndWith(256)
			}
			ip[byteIndex] = (r.firstIP[byteIndex] & fixedMask) | (ip[byteIndex] & randomMask)
			r.appendIP(ip)
			r.firstIP[byteIndex] += step
			if r.firstIP[byteIndex] == 0 {
				incrementIP(r.firstIP, byteIndex-1, 12)
			}
		}
	}
}

func (r *IPRanges) chooseIPv6() {
	if Mask > 128 || Mask <= 0 {
		Mask = 54
	}
	if r.mask == "/128" { // 单个 IP 则无需随机，直接加入自身即可
		r.appendIP(r.firstIP)
	} else {
		byteIndex, _, fixedMask, randomMask, step := calcMaskValues(Mask)
		for r.ipNet.Contains(r.firstIP) {
			ip := make(net.IP, len(r.firstIP))
			copy(ip, r.firstIP)
			for i := byteIndex; i < 16; i++ {
				ip[i] = randIPEndWith(256)
			}
			ip[byteIndex] = (r.firstIP[byteIndex] & fixedMask) | (ip[byteIndex] & randomMask)
			r.appendIP(ip)
			r.firstIP[byteIndex] += step
			if r.firstIP[byteIndex] == 0 {
				incrementIP(r.firstIP, byteIndex-1, 0)
			}
		}
	}
}

func loadIPRanges() []*net.IPAddr {
	ranges := newIPRanges()
	if IPText != "" { // 从参数中获取 IP 段数据
		IPs := strings.Split(IPText, ",") // 以逗号分隔为数组并循环遍历
		for _, IP := range IPs {
			IP = strings.TrimSpace(IP) // 去除首尾的空白字符（空格、制表符、换行符等）
			if IP == "" {              // 跳过空的（即开头、结尾或连续多个 ,, 的情况）
				continue
			}
			ranges.parseCIDR(IP) // 解析 IP 段，获得 IP、IP 范围、子网掩码
			if isIPv4(IP) {      // 生成要测速的所有 IPv4 / IPv6 地址（单个/随机/全部）
				ranges.chooseIPv4()
			} else {
				ranges.chooseIPv6()
			}
		}
	} else { // 从文件中获取 IP 段数据
		if IPFile == "" {
			IPFile = defaultInputFile
		}
		file, err := os.Open(IPFile)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() { // 循环遍历文件每一行
			line := strings.TrimSpace(scanner.Text()) // 去除首尾的空白字符（空格、制表符、换行符等）
			if line == "" {                           // 跳过空行
				continue
			}
			ranges.parseCIDR(line) // 解析 IP 段，获得 IP、IP 范围、子网掩码
			if isIPv4(line) {      // 生成要测速的所有 IPv4 / IPv6 地址（单个/随机/全部）
				ranges.chooseIPv4()
			} else {
				ranges.chooseIPv6()
			}
		}
	}
	return ranges.ips
}
