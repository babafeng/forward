// Package vless 提供 VLESS 协议的公共编解码功能。
// vision.go 封装 xtls-rprx-vision 流所需的 unsafe 缓冲区获取逻辑。
package vless

import (
	"bytes"
	gotls "crypto/tls"
	"fmt"
	"reflect"
	"unsafe"

	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// VisionInputBuffers 从 TLS/Reality 连接中获取 xtls-rprx-vision 流所需的内部
// 缓冲区指针。这些指针直接指向 xtls 库内部的未导出字段，因此必须通过
// reflect + unsafe 来访问。
//
// 警告: 如果 xtls/xray-core 更新了 Conn 结构体的字段布局，此函数可能会
// 返回错误而非静默失败——所有字段类型都会被运行时检查。
func VisionInputBuffers(conn interface{}) (*bytes.Reader, *bytes.Buffer, error) {
	// Unwrap stat counter wrapper if present
	if statConn, ok := conn.(*stat.CounterConnection); ok {
		conn = statConn.Connection
	}

	switch c := conn.(type) {
	case *tls.Conn:
		if c.ConnectionState().Version != gotls.VersionTLS13 {
			return nil, nil, fmt.Errorf("xtls-rprx-vision requires TLS 1.3")
		}
		return xtlsBuffers(c.Conn)
	case *tls.UConn:
		if c.ConnectionState().Version != gotls.VersionTLS13 {
			return nil, nil, fmt.Errorf("xtls-rprx-vision requires TLS 1.3")
		}
		if c.UConn == nil || c.UConn.Conn == nil {
			return nil, nil, fmt.Errorf("xtls-rprx-vision requires valid tls uconn")
		}
		return xtlsBuffers(c.UConn.Conn)
	case *reality.UConn:
		if c.UConn == nil || c.UConn.Conn == nil {
			return nil, nil, fmt.Errorf("xtls-rprx-vision requires valid reality uconn")
		}
		return xtlsBuffers(c.UConn.Conn)
	case *reality.Conn:
		return xtlsBuffers(c)
	default:
		return nil, nil, fmt.Errorf("xtls-rprx-vision requires TLS or REALITY")
	}
}

// xtlsBuffers 通过反射获取 xtls 内部的 input 和 rawInput 缓冲区。
// 使用 unsafe.Pointer 直接按字段偏移量访问未导出成员。
func xtlsBuffers(conn any) (*bytes.Reader, *bytes.Buffer, error) {
	val := reflect.ValueOf(conn)
	if val.Kind() != reflect.Ptr || val.IsNil() {
		return nil, nil, fmt.Errorf("invalid xtls connection")
	}

	t := val.Type().Elem()
	inputField, ok := t.FieldByName("input")
	if !ok {
		return nil, nil, fmt.Errorf("missing xtls input buffer")
	}

	rawInputField, ok := t.FieldByName("rawInput")
	if !ok {
		return nil, nil, fmt.Errorf("missing xtls rawInput buffer")
	}

	if inputField.Type != reflect.TypeOf(bytes.Reader{}) {
		return nil, nil, fmt.Errorf("xtls input field type mismatch: expected bytes.Reader, got %v", inputField.Type)
	}
	if rawInputField.Type != reflect.TypeOf(bytes.Buffer{}) {
		return nil, nil, fmt.Errorf("xtls rawInput field type mismatch: expected bytes.Buffer, got %v", rawInputField.Type)
	}

	inputPtr, err := xtlsFieldPointer(val, inputField)
	if err != nil {
		return nil, nil, err
	}
	rawInputPtr, err := xtlsFieldPointer(val, rawInputField)
	if err != nil {
		return nil, nil, err
	}
	input := (*bytes.Reader)(inputPtr)
	rawInput := (*bytes.Buffer)(rawInputPtr)

	if input == nil || rawInput == nil {
		return nil, nil, fmt.Errorf("xtls input buffers not initialized")
	}

	return input, rawInput, nil
}

func xtlsFieldPointer(root reflect.Value, field reflect.StructField) (unsafe.Pointer, error) {
	ptr := root.UnsafePointer()
	typ := root.Type().Elem()
	for i, idx := range field.Index {
		if typ.Kind() != reflect.Struct || idx < 0 || idx >= typ.NumField() {
			return nil, fmt.Errorf("invalid xtls field path for %s", field.Name)
		}
		sf := typ.Field(idx)
		ptr = unsafe.Add(ptr, sf.Offset)
		if i == len(field.Index)-1 {
			return ptr, nil
		}
		if sf.Type.Kind() == reflect.Ptr {
			ptr = *(*unsafe.Pointer)(ptr)
			if ptr == nil {
				return nil, fmt.Errorf("nil embedded xtls field %s", sf.Name)
			}
			typ = sf.Type.Elem()
			continue
		}
		typ = sf.Type
	}
	return nil, fmt.Errorf("invalid xtls field path for %s", field.Name)
}
