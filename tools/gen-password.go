package main

import (
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run gen-password.go <password>")
		os.Exit(1)
	}

	password := os.Args[1]
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Bcrypt hash for '%s':\n%s\n", password, string(hash))
	fmt.Println("\nAdd this to your config.yaml under auth.users:")
	fmt.Printf("password: \"%s\"\n", string(hash))
}
