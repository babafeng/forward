package socks5

func Contains(arr []byte, v byte) bool {
	for _, b := range arr {
		if b == v {
			return true
		}
	}
	return false
}
