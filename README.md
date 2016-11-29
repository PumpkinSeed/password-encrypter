# Golang password encrypter
##### Based on Symfony PHP framework User Manager password encryption

#### Installation
```
go get github.com/PumpkinSeed/password-encrypter
```

#### Usage
```
package main

import (
    "github.com/PumpkinSeed/password-encrypter"
    "fmt"
)

func main() {
    encryption := encrypter.New(map[string]string{
        "iteration": "5000",
        "saltLength": "32",
    })
    var err error

    // Hash the password
    digest, salt, err := encryption.HashPassword("SecretPassword")
    if err != nil {
        fmt.Println(err)
    }

    // Verify password
    err = VerifyPassword("password hash", "plain password", salt)
    if err != nil {
        fmt.Println(err)
    }
}
```
