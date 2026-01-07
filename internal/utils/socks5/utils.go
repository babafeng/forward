package socks5

// Contains 检查 byte slice 是否包含指定值
func Contains(arr []byte, v byte) bool {
	for _, b := range arr {
		if b == v {
			return true
		}
	}
	return false
}
