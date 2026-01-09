package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	xcore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"

	"forward/internal/utils/crypto"
)

func main() {
	// 生成 X25519 密钥对
	privKey, pubKey, err := crypto.GenerateX25519Keys()
	if err != nil {
		log.Fatalf("Generate X25519 keys error: %v", err)
	}

	// 生成随机 UUID
	userUUID := crypto.GenerateUUID()

	// 生成 shortId
	shortId := crypto.GenerateShortID(4)

	// Reality 配置
	serverPort := uint32(8443)
	destSite := "www.apple.com:443"
	serverName := "www.apple.com"

	// 使用 xray-core 的 conf 包构建配置
	jsonConfig := fmt.Sprintf(`{
		"log": {
			"loglevel": "warning"
		},
		"inbounds": [{
			"listen": "0.0.0.0",
			"port": %d,
			"protocol": "vless",
			"settings": {
				"clients": [{
					"id": "%s",
					"flow": "xtls-rprx-vision"
				}],
				"decryption": "none"
			},
			"streamSettings": {
				"network": "tcp",
				"security": "reality",
				"realitySettings": {
					"show": false,
					"dest": "%s",
					"xver": 0,
					"serverNames": ["%s"],
					"privateKey": "%s",
					"shortIds": ["%s"]
				}
			}
		}],
		"outbounds": [{
			"protocol": "freedom",
			"tag": "direct"
		}]
	}`, serverPort, userUUID, destSite, serverName, privKey, shortId)

	// 解析 JSON 配置
	xrayConf := &conf.Config{}
	if err := json.Unmarshal([]byte(jsonConfig), xrayConf); err != nil {
		log.Fatalf("Unmarshal config error: %v", err)
	}

	pbConfig, err := xrayConf.Build()
	if err != nil {
		log.Fatalf("Build config error: %v", err)
	}

	// 启动 Xray
	server, err := xcore.New(pbConfig)
	if err != nil {
		log.Fatalf("Create xray server error: %v", err)
	}

	if err := server.Start(); err != nil {
		log.Fatalf("Start xray server error: %v", err)
	}

	// 打印配置信息
	fmt.Println("========================================")
	fmt.Println("VLESS + Reality Server Started!")
	fmt.Println("========================================")
	fmt.Printf("Listen: 0.0.0.0:%d\n", serverPort)
	fmt.Printf("UUID: %s\n", userUUID)
	fmt.Printf("Flow: xtls-rprx-vision\n")
	fmt.Printf("Public Key: %s\n", pubKey)
	fmt.Printf("Short ID: %s\n", shortId)
	fmt.Printf("SNI: %s\n", serverName)
	fmt.Println("========================================")

	// 生成 Shadowrocket URL
	params := url.Values{}
	params.Set("encryption", "none")
	params.Set("flow", "xtls-rprx-vision")
	params.Set("security", "reality")
	params.Set("sni", serverName)
	params.Set("fp", "chrome")
	params.Set("pbk", pubKey)
	params.Set("sid", shortId)
	params.Set("type", "tcp")

	shadowrocketURL := fmt.Sprintf("vless://%s@YOUR_SERVER_IP:%d?%s#VLESS-Reality",
		userUUID, serverPort, params.Encode())

	fmt.Println("\n📱 Shadowrocket URL (请将 YOUR_SERVER_IP 替换为你的服务器 IP):")
	fmt.Println(shadowrocketURL)

	fmt.Println("\n📋 Base64 URL:")
	fmt.Println(base64.StdEncoding.EncodeToString([]byte(shadowrocketURL)))

	fmt.Println("\n按 Ctrl+C 停止服务器...")

	// 避免 unused import
	_ = serial.LoadJSONConfig

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	server.Close()
	fmt.Println("\nServer stopped.")
}
