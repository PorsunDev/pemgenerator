package pemgen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func GenerateKeys() {
	env := flag.String("env", "prod", "for production uses")
	flag.Parse()

	storagePath := GetStoragePath()
	isTestEnv := env != nil && *env == "dev"
	if isTestEnv {
		fmt.Println("Running in development environment: Keys will be saved in current directory")
	} else {
		fmt.Printf("Running in production environment: Keys will be saved to %s\n", storagePath)
	}

	if isTestEnv {
		storagePath = ""
	} else {
		mode := os.FileMode(0700)
		if runtime.GOOS == "windows" {
			mode = os.FileMode(0o600)
		}
		err := os.MkdirAll(storagePath, mode)
		if err != nil {
			fmt.Printf("Failed to create directory: %v\n", err)
			return
		}
	}

	// 1. Generate RSA private key (2048 bits is standard)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("Failed to generate key: %v\n", err)
		return
	}

	// 2. Save Private Key to PEM file
	privateFile, err := os.Create(filepath.Join(storagePath, "private.pem"))
	if err != nil {
		fmt.Printf("Failed to create private.pem: %v\n", err)
		return
	}
	defer privateFile.Close()

	privateBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	if err := pem.Encode(privateFile, privateBlock); err != nil {
		fmt.Printf("Failed to write private key: %v\n", err)
		return
	}

	// 3. Save Public Key to PEM file
	publicKey := &privateKey.PublicKey
	publicFile, err := os.Create(filepath.Join(storagePath, "public.pem"))
	if err != nil {
		fmt.Printf("Failed to create public.pem: %v\n", err)
		return
	}
	defer publicFile.Close()

	// Use PKIX for standard public key format
	publicBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		fmt.Printf("Failed to marshal public key: %v\n", err)
		return
	}

	publicBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicBytes,
	}
	if err := pem.Encode(publicFile, publicBlock); err != nil {
		fmt.Printf("Failed to write public key: %v\n", err)
		return
	}

	fmt.Println("Keys successfully generated and saved to .pem files")

	if !isTestEnv {
		fmt.Printf("Setting permissions for production environment...\n")
		err = restrictPermissions(storagePath)
		if err != nil {
			fmt.Printf("Failed to set permissions: %v\n", err)
			return
		}
		fmt.Println("Permissions set: private.pem (400), public.pem (444), storage directory (700)")
	}
}

func GetStoragePath() string {
	key_path := os.Getenv("key_path")
	// Check if the path starts with a tilde
	if strings.HasPrefix(key_path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Println("Error getting home directory:", err)
			return key_path // Return the original path if we can't get the home directory
		}
		// Swap the tilde for the real home directory path
		key_path = filepath.Join(home, key_path[2:])
	}
	return key_path
}

func grantPermissions(storagePath string) error {
	mode := os.FileMode(0700)
	if runtime.GOOS == "windows" {
		mode = os.FileMode(0o600)
	}
	err := os.Chmod(filepath.Join(storagePath), mode)
	if err != nil {
		fmt.Printf("Failed to set permissions on storage directory: %v\n", err)
		return err
	}
	err = os.Chmod(filepath.Join(storagePath, "private.pem"), mode)
	if err != nil {
		fmt.Printf("Failed to set permissions on private.pem: %v\n", err)
		return err
	}
	err = os.Chmod(filepath.Join(storagePath, "public.pem"), mode)
	if err != nil {
		fmt.Printf("Failed to set permissions on public.pem: %v\n", err)
		return err
	}
	return nil
}

func restrictPermissions(storagePath string) error {
	readonlymodePrivateKey := os.FileMode(0400)
	readonlymodePublicKey := os.FileMode(0444)
	if runtime.GOOS == "windows" {
		readonlymodePrivateKey = os.FileMode(0o400)
		readonlymodePublicKey = os.FileMode(0o444)
	}
	err := os.Chmod(filepath.Join(storagePath), 0700)
	if err != nil {
		fmt.Printf("Failed to set permissions on storage directory: %v\n", err)
		return err
	}
	err = os.Chmod(filepath.Join(storagePath, "private.pem"), readonlymodePrivateKey)
	if err != nil {
		fmt.Printf("Failed to set permissions on private.pem: %v\n", err)
		return err
	}
	err = os.Chmod(filepath.Join(storagePath, "public.pem"), readonlymodePublicKey)
	if err != nil {
		fmt.Printf("Failed to set permissions on public.pem: %v\n", err)
		return err
	}
	return nil
}
