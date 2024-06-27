package verifyx

import "github.com/golang-jwt/jwt"

const verifyxURL string = "https://verifyx.developers-api.com"

type Client struct {
	IdKey     string
	SecretKey string
}

func NewClient(idKey string, secretKey string) (*Client, error) {
	return &Client{
		IdKey:     idKey,
		SecretKey: secretKey,
	}, nil
}

func generateAppToken(idkey string, secretKey []byte) (string, error) {
	// Crear el mapa de claims para el JWT. Incluye los datos del usuario y la fecha de expiración.
	payload := jwt.MapClaims{
		"app_id": idkey,
	}

	// Crear un nuevo token JWT usando HMAC SHA256 como el método de firma.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)

	// Firmar el token con la clave secreta y convertirlo a una cadena.
	tokenStr, err := token.SignedString(secretKey)
	if err != nil {
		// En caso de error al firmar el token, retorna un error personalizado con código de estado 500.
		return tokenStr, err
	}

	// Retorna el token, el tiempo de expiración y nil como error si todo fue exitoso.
	return tokenStr, nil
}
