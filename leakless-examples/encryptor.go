package main

import (
    "fmt"
    "io/ioutil"
    "os"
    "strings"
)

func main() {
    fmt.Println("Starting file modification process...")
    // Path to the file to modify
    // Check for command-line arguments
    if len(os.Args) < 3 {
        fmt.Println("No file name provided")
        return
    }

    // Get the filename from command line arguments
    filename := os.Args[2]
    tempDir := "./temp"
    tempFilename := tempDir + "/main.go"

    // Ensure temp directory exists
    if _, err := os.Stat(tempDir); os.IsNotExist(err) {
        if err = os.Mkdir(tempDir, 0755); err != nil {
            fmt.Println("Failed to create temp directory:", err)
            return
        }
    }

    // Read the original file content
    content, err := ioutil.ReadFile(filename)
    if err != nil {
        fmt.Println("Error reading file:", err)
        return
    }

    lines := strings.Split(string(content), "\n")
    modifiedContent := ""

    // Variable to check if the next line should be modified
    modifyNextLine := false

    // Iterate over each line
    for _, line := range lines {
        if modifyNextLine {
            // Find the index of the equal sign to split variable name from value
            index := strings.Index(line, "=")
            if index != -1 {
                // Keep everything before the "=" and change only after it
                modifiedContent += line[:index+1] + ` "New Secret Message!"` + "\n"
            } else {
                modifiedContent += line + "\n" // If no "=" found, just copy the line as is
            }
            modifyNextLine = false
        } else {
            modifiedContent += line + "\n"
        }

        // Check if this line has the special comment
        if strings.Contains(line, "LEAKLESS_SECRET") {
            modifyNextLine = true
        }
    }

    // Write the modified content to a new temporary file
    err = ioutil.WriteFile(tempFilename, []byte(modifiedContent), 0644)
    if err != nil {
        fmt.Println("Failed to write modified content to file:", err)
        return
    }

    fmt.Println("File modification completed successfully.")
}
