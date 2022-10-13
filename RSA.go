package InverseAlgorithm1

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// GenerateRSAKey 生成RSA私钥和公钥，保存到文件中
func GenerateRSAKey(bits int) {
	//GenerateKey函数使用随机数据生成器random生成一对具有指定字位数的RSA密钥
	//Reader是一个全局、共享的密码用强随机数生成器
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}
	//保存私钥
	//通过x509标准将得到的ras私钥序列化为ASN.1 的 DER编码字符串
	// X509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey) // PKCS1 和 9 是不一致的
	X509PrivateKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(0)
	}
	//使用pem格式对x509输出的内容进行编码
	//创建文件保存私钥
	privateFile, err := os.Create("private.pem")
	if err != nil {
		panic(err)
	}
	defer func(privateFile *os.File) {
		err := privateFile.Close()
		if err != nil {

		}
	}(privateFile)
	//构建一个pem.Block结构体对象
	privateBlock := pem.Block{Type: "PRIVATE KEY", Bytes: X509PrivateKey}
	//将数据保存到文件
	err = pem.Encode(privateFile, &privateBlock)
	if err != nil {
		return
	}
	//保存公钥
	//获取公钥的数据
	publicKey := privateKey.PublicKey
	//X509对公钥编码
	X509PublicKey, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		panic(err)
	}
	//pem格式编码
	//创建用于保存公钥的文件
	publicFile, err := os.Create("public.pem")
	if err != nil {
		panic(err)
	}
	defer func(publicFile *os.File) {
		err := publicFile.Close()
		if err != nil {

		}
	}(publicFile)
	//创建一个pem.Block结构体对象
	publicBlock := pem.Block{Type: "Public Key", Bytes: X509PublicKey}
	//保存到文件
	err = pem.Encode(publicFile, &publicBlock)
	if err != nil {
		return
	}
}

// RsaEncrypt RSA加密
func RsaEncrypt(plainText []byte, path string) []byte {
	//打开文件
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)
	//读取文件的内容
	info, _ := file.Stat()
	buf := make([]byte, info.Size())
	_, _ = file.Read(buf)
	//pem解码
	block, _ := pem.Decode(buf)
	//x509解码
	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	//类型断言
	publicKey := publicKeyInterface.(*rsa.PublicKey)
	//对明文进行加密
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plainText)
	if err != nil {
		panic(err)
	}
	//返回密文
	return cipherText
}

// RsaDecrypt RSA解密
func RsaDecrypt(cipherText []byte, path string) []byte {
	//打开文件
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer func(file *os.File) {
		err = file.Close()
		if err != nil {
			panic(err)
		}
	}(file)
	//获取文件内容
	info, _ := file.Stat()
	buf := make([]byte, info.Size())
	_, _ = file.Read(buf)
	//pem解码
	block, _ := pem.Decode(buf)
	//X509解码
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(0)
	}
	//对密文进行解密
	plainText, _ := rsa.DecryptPKCS1v15(rand.Reader, privateKey.(*rsa.PrivateKey), cipherText)
	//返回明文
	return plainText
}

//func main() {
//	// RSA/ECB/PKCS1Padding
//	// RSA是算法，ECB是分块模式，PKCS1Padding是填充模式
//
//	// pkcs1私钥生成openssl genrsa -out pkcs1.pem 1024
//	// pkcs1转pkcs8私钥 ：openssl pkcs8 -in pkcs8.pem -nocrypt -out pkcs1.pem
//
//	// pkcs1 BEGIN RSA PRIVATE KEY
//	// pkcs8 BEGIN PRIVATE KEY
//
//	GenerateRSAKey(1024)
//	publicPath := "public_key.pem"
//	privatePath := "private_key.pem"
//
//	publicPath = "public.pem"
//	privatePath = "private.pem"
//
//	txt := []byte("hello")
//	encrptTxt := RsaEncrypt(txt, publicPath)
//	decrptCode := RsaDecrypt(encrptTxt, privatePath)
//	fmt.Println(string(decrptCode))
//
//}
