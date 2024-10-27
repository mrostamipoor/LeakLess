package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "errors"
    "fmt"
    "io/ioutil"
    "os"
    "strings"
    "bytes"
)


var iv = []byte{45, 67, 89, 12, 34, 56, 78, 90, 12, 34, 56, 78, 90, 12, 34, 56}


func encrypt(data, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    if len(data) == 0 {
        return nil, errors.New("plaintext empty")
    }

 
    padding := block.BlockSize() - len(data)%block.BlockSize()
    paddedData := append(data, bytes.Repeat([]byte{byte(padding)}, padding)...)

    
    mode := cipher.NewCBCEncrypter(block, iv)
    encrypted := make([]byte, len(paddedData))
    mode.CryptBlocks(encrypted, paddedData)

    return encrypted, nil
}

func generateCryptoKey() ([]byte, error) {
    key := make([]byte, 16)

    _, err := rand.Read(key)
    if err != nil {
        return nil, err 
    }

    return key, nil
}

func main() {
    randomKey, err := generateCryptoKey()
    if err != nil {
        panic(err) 
    }

    moduleid :=""
    if _, err1 := os.Stat("signal"); os.IsNotExist(err1) {
        fmt.Println("signal is not created!")
    } else{
        content, err := ioutil.ReadFile("signal")
        if err != nil {
            fmt.Println("Error reading file:", err)
            return
        }
        moduleid =string(content)
    }

    encodedKey := base64.StdEncoding.EncodeToString(randomKey)
    writtenString :=moduleid+":::"+encodedKey
    err = ioutil.WriteFile("key_moduleid", []byte(writtenString), 0644)
    if err != nil {
        fmt.Println("Failed to write key to file:", err)
        return
    }

    if len(os.Args) < 3 {
        fmt.Println("No file name provided")
        return
    }
    filename := os.Args[2]
    tempDir := "./tmp"
    tempFilename := tempDir +"/"+ filename


    //data := []byte("secret_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")  
	//key := []byte{69, 96, 47, 57, 249, 37, 15, 67, 231, 118, 123, 177, 16, 249, 205, 134}

    // Key should be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256
    //[69, 96, 47, 57, 249, 37, 15, 67, 231, 118, 123, 177, 16, 249, 205, 134]

	/*encryptedData, err := encrypt(data, key)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Encrypted: %x\n", encryptedData)
*/

    //fmt.Println(moduleid)
    if _, err := os.Stat(tempDir); os.IsNotExist(err) {
        if err = os.Mkdir(tempDir, 0755); err != nil {
            fmt.Println("Failed to create temp directory:", err)
            return
        }
    }

    content, err := ioutil.ReadFile(filename)
    if err != nil {
        fmt.Println("Error reading file:", err)
        return
    }

    lines := strings.Split(string(content), "\n")
    modifiedContent := ""
    modifyNextLine := false

    for _, line := range lines {
        if modifyNextLine {
            index := strings.Index(line, "=")
            if index != -1 {
                originalValueStart := strings.Index(line[index:], "\"") + index + 1
                originalValueEnd := strings.LastIndex(line, "\"")
                originalValue := line[originalValueStart:originalValueEnd]

                encryptedData, err := encrypt([]byte(originalValue), randomKey)
                if err != nil {
                    fmt.Println("Encryption failed:", err)
                    return
                }
                prefix := "LEAKLESS_"
                suffix := "_LEAKLESS"
                base64EncryptedData := base64.StdEncoding.EncodeToString(encryptedData)
                finalData := fmt.Sprintf("%s%s%s", prefix, base64EncryptedData, suffix)
                modifiedContent += line[:index+1] + ` "` + finalData + `"` + "\n"
            } else {
                modifiedContent += line + "\n"
            }
            modifyNextLine = false
        } else {
            modifiedContent += line + "\n"
        }

        if strings.Contains(line, "LEAKLESS_SECRET") {
            modifyNextLine = true
        }
    }

    err = ioutil.WriteFile(tempFilename, []byte(modifiedContent), 0644)
    if err != nil {
        fmt.Println("Failed to write modified content to file:", err)
        return
    }

    fmt.Println("File modification completed successfully.")
}
