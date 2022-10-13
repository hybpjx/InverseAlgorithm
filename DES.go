package InverseAlgorithm1

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
)

func DesCBCEncrypt(data, key, iv []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	data = pkcs5Padding(data, block.BlockSize())
	cryptText := make([]byte, len(data))

	blockMode := cipher.NewCBCEncrypter(block, iv)
	blockMode.CryptBlocks(cryptText, data)
	return cryptText, nil
}

func pkcs5Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padText...)
}

//func main() {
//	data := []byte("hello world")
//	key := []byte("12345678")
//	iv := []byte("43218765")
//
//	result, err := DesCBCEncrypt(data, key, iv)
//	if err != nil {
//		fmt.Println(err)
//	}
//	b := hex.EncodeToString(result)
//	fmt.Println(b)
//}
