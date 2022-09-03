package AES

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

func AesEncryptCFB(origData []byte, key []byte) (encrypted []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	encrypted = make([]byte, aes.BlockSize+len(origData))
	iv := encrypted[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(encrypted[aes.BlockSize:], origData)
	return encrypted
}

func AesDecryptCFB(encrypted []byte, key []byte) (decrypted []byte) {
	block, _ := aes.NewCipher(key)
	if len(encrypted) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := encrypted[:aes.BlockSize]
	encrypted = encrypted[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(encrypted, encrypted)
	return encrypted
}

//func main() {
//	origData := []byte("460154561234") // 待加密的数据
//	key := []byte("9876787656785679")  // 加密的密钥
//	log.Println("原文：", string(origData))
//
//	log.Println("------------------ CFB模式 --------------------")
//	encrypted := AesEncryptCFB(origData, key)
//	log.Println("密文(hex)：", hex.EncodeToString(encrypted))
//	log.Println("密文(base64)：", base64.StdEncoding.EncodeToString(encrypted))
//	decrypted := AesDecryptCFB(encrypted, key)
//	log.Println("解密结果：", string(decrypted))
//}
