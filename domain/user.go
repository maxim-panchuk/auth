package domain

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type LoginCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
