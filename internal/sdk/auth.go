package sdk

const (
	AuthMethodAPIKey = "api_key"
	AuthMethodBearer = "bearer"
)

type Auth struct {
	Method string
	Token  string
}
