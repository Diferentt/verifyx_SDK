package verifyx

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type ResponseData struct {
	AccessToken  string            `json:"access_token"`
	RefreshToken string            `json:"refresh_token"`
	IDToken      string            `json:"id_token"`
	Permissions  map[string]string `json:"permissions"`
}

// Signin function receives email and password and returns access token
func (c *Client) SignIn(email string, password string) (ResponseData, error) {
	const myUrl string = "/signin"
	appToken, err := generateAppToken(c.IdKey, []byte(c.SecretKey))
	if err != nil {
		return ResponseData{}, err
	}

	credentials := Credentials{
		Email:    email,
		Password: password,
	}

	jsonData, err := json.Marshal(credentials)
	if err != nil {
		return ResponseData{}, err
	}

	req, err := http.NewRequest("POST", verifyxURL+myUrl, bytes.NewBuffer(jsonData))
	if err != nil {
		return ResponseData{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+appToken)

	// Cliente HTTP para realizar la solicitud
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return ResponseData{}, err
	}
	defer resp.Body.Close()

	// Leer la respuesta
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ResponseData{}, err
	}

	var responseData ResponseData
	err = json.Unmarshal(body, &responseData)
	if err != nil {
		return ResponseData{}, err
	}

	return responseData, nil
}

type SignUpData struct {
	Email             string `json:"email"`
	Password          string `json:"password"`
	PasswordConfirmed string `json:"password_confirmed"`
}

// Signin function receives email and password and returns access token
func (c *Client) SignUp(email string, password string, password_confirmed string, token string) error {
	const myUrl string = "/signup"
	appToken, err := generateAppToken(c.IdKey, []byte(c.SecretKey))
	if err != nil {
		return err
	}

	data := SignUpData{
		Email:             email,
		Password:          password,
		PasswordConfirmed: password_confirmed,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", verifyxURL+myUrl, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+appToken+" "+token)

	// Cliente HTTP para realizar la solicitud
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Leer la respuesta
	_, err = io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	return nil
}

type ForgotData struct {
	Email string `json:"email"`
}

func (c *Client) ForgotPassword(email string) error {
	const myUrl string = "/forgot"
	appToken, err := generateAppToken(c.IdKey, []byte(c.SecretKey))
	if err != nil {
		return err
	}

	data := ForgotData{
		Email: email,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", verifyxURL+myUrl, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+appToken)

	// Cliente HTTP para realizar la solicitud
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Leer la respuesta
	_, err = io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	return nil
}

type RefreshCredentials struct {
	RefreshToken string `json:"refresh_token"`
}

func (c *Client) RefreshAccessToken(refreshToken string) (ResponseData, error) {
	const myUrl string = "/token"
	appToken, err := generateAppToken(c.IdKey, []byte(c.SecretKey))
	if err != nil {
		return ResponseData{}, err
	}

	jsonData, err := json.Marshal(RefreshCredentials{
		RefreshToken: refreshToken,
	})
	if err != nil {
		return ResponseData{}, err
	}

	req, err := http.NewRequest("POST", verifyxURL+myUrl, bytes.NewBuffer(jsonData))
	if err != nil {
		return ResponseData{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+appToken)

	// Cliente HTTP para realizar la solicitud
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return ResponseData{}, err
	}
	defer resp.Body.Close()

	// Leer la respuesta
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ResponseData{}, err
	}

	var responseData ResponseData
	err = json.Unmarshal(body, &responseData)
	if err != nil {
		return ResponseData{}, err
	}

	return responseData, nil
}

type ConfirmForgotPassword struct {
	Code              string `json:"code"`
	Email             string `json:"email"`
	Password          string `json:"password"`
	PasswordConfirmed string `json:"password_confirmed"`
}

func (c *Client) ConfirmForgotPassword(email string, password string, password_confirmed string, code string) error {
	const myUrl string = "/forgot/confirm"
	appToken, err := generateAppToken(c.IdKey, []byte(c.SecretKey))
	if err != nil {
		return err
	}

	data := ConfirmForgotPassword{
		Email:             email,
		Password:          password,
		PasswordConfirmed: password_confirmed,
		Code:              code,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", verifyxURL+myUrl, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+appToken)

	// Cliente HTTP para realizar la solicitud
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Leer la respuesta
	_, err = io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	return nil
}
