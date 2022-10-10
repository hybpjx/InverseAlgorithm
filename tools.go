package InverseAlgorithm1


import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// MD5Str md5验证
func MD5Str(src string) string {
	h := md5.New()
	h.Write([]byte(src)) // 需要加密的字符串为
	//fmt.Printf("%s\n", hex.EncodeToString(h.Sum(nil))) // 输出加密结果
	return hex.EncodeToString(h.Sum(nil))
}

// MD5Str2 md5验证
func MD5Str2(src string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(src)))
}

//key随意设置 data 要加密数据

func Hmac(key, data string) string {
	// 创建对应的md5哈希加密算法
	hash:= hmac.New(md5.New, []byte(key))

	hash.Write([]byte(data))

	return hex.EncodeToString(hash.Sum([]byte("")))

}


// HmacSha1 hmacSha1加密 key随意设置 data 要加密数据
func HmacSha1(src, key string) string {
	m := hmac.New(sha1.New, []byte(key))
	m.Write([]byte(src))
	return hex.EncodeToString(m.Sum(nil))
}


// HmacSHA256 hmacSha256加密 key随意设置 data 要加密数据
func HmacSHA256(key, src string) string {
	m := hmac.New(sha256.New, []byte(key))
	m.Write([]byte(src))
	return hex.EncodeToString(m.Sum(nil))
}


// HmacSHA512 hmacSha512加密
func HmacSHA512(key, src string) string {
	m := hmac.New(sha512.New, []byte(key))
	m.Write([]byte(src))
	return hex.EncodeToString(m.Sum(nil))
}

// Sha1 sha1 加密
func Sha1(data string) string {
	sha1_ := sha1.New()
	sha1_.Write([]byte(data))
	return hex.EncodeToString(sha1_.Sum([]byte("")))
}

// SHA256 sha256加密
func SHA256(src string) string {
	h := sha256.New()
	// 需要加密的字符串为
	h.Write([]byte(src))
	// fmt.Printf("%s\n", hex.EncodeToString(h.Sum(nil))) // 输出加密结果
	return hex.EncodeToString(h.Sum(nil))
}

// SHA512 sha512加密
func SHA512(src string) string {
	h := sha512.New()
	// 需要加密的字符串为
	h.Write([]byte(src))
	// fmt.Printf("%s\n", hex.EncodeToString(h.Sum(nil))) // 输出加密结果
	return hex.EncodeToString(h.Sum(nil))
}


// BASE64StdEncode base编码
func BASE64StdEncode(src string) string {
	return base64.StdEncoding.EncodeToString([]byte(src))
}

// BASE64StdDecode base解码
func BASE64StdDecode(src string) string {
	a, err := base64.StdEncoding.DecodeString(src)
	if err != nil {
		_ = fmt.Errorf("解密失败,%v\n", err)
	}
	return string(a)
}