package format

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
)

func ToHashSHA256(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// Fungsi untuk membuat hash SHA-256 dari passphrase
func createHash(key string) []byte {
	hash := sha256.Sum256([]byte(key))
	return hash[:]
}

// Fungsi untuk menambah padding
func pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// Fungsi untuk menghapus padding
func unpad(data []byte) ([]byte, error) {
	length := len(data)
	unpadding := int(data[length-1])
	if unpadding > length {
		return nil, errors.New("unpadding size is too large")
	}
	return data[:(length - unpadding)], nil
}

// Fungsi untuk Encrypt
func Encrypt(text, passphrase string) (string, error) {
	key := createHash(passphrase)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Mengisi nonce dengan random bytes
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Menambah padding pada plaintext
	paddedText := pad([]byte(text), aes.BlockSize)
	ciphertext := aesGCM.Seal(nonce, nonce, paddedText, nil)

	return hex.EncodeToString(ciphertext), nil
}

// Fungsi untuk Decrypt
func Decrypt(encryptedText, passphrase string) (string, error) {
	key := createHash(passphrase)
	ciphertext, _ := hex.DecodeString(encryptedText)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Memisahkan nonce dari ciphertext
	nonceSize := aesGCM.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Mendekripsi ciphertext
	paddedText, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	// Menghapus padding setelah dekripsi
	plaintext, err := unpad(paddedText)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
