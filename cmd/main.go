package main

import (
	"log"

	verifyx "github.com/Diferentt/verifyx_sdk"
)

func main() {
	client, err := verifyx.NewClient("667c1f9ca474ffa2770ba243", "7a697e5e947c167545525abce680756f")
	if err != nil {
		log.Fatalln(err)
	}
	//token, _ := client.SignIn("sfara.gonzalo@gmail.com", "@Sarasa123")

	//log.Println(client.RefreshAccessToken(token.RefreshToken))

	//log.Println(client.SignUp("gonzasfara@gmail.com", "@Sarasa123", "@Sarasa123", token.AccessToken))

	//log.Println(client.ForgotPassword("nicolas.debole@findholding.com"))
	log.Println(client.ConfirmForgotPassword("nicolas.debole@findholding.com", "@Hola1234", "@Hola1234", "966603"))
}
