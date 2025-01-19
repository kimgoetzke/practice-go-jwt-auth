package main

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func Test_UserRegistration(t *testing.T) {
	scenarios := []struct {
		name           string
		method         string
		formData       string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Method not allowed",
			method:         http.MethodGet,
			formData:       "",
			expectedStatus: 405,
			expectedBody:   "Method not allowed\n",
		},
		{
			name:           "Invalid username or password",
			method:         http.MethodPost,
			formData:       "username=ab&password=1234567",
			expectedStatus: 406,
			expectedBody:   "Invalid username and/or password\n",
		},
		{
			name:           "Successful registration",
			method:         http.MethodPost,
			formData:       "username=abcd&password=12345678",
			expectedStatus: 200,
			expectedBody:   "User registered successfully",
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			req := httptest.NewRequest(scenario.method, "/register", strings.NewReader(scenario.formData))
			if scenario.method == http.MethodPost {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			rr := httptest.NewRecorder()
			register(rr, req)
			assert.Equal(t, scenario.expectedStatus, rr.Code)
			assert.Equal(t, scenario.expectedBody, rr.Body.String())
		})
	}
}

func Test_UserLogin(t *testing.T) {
	scenarios := []struct {
		name               string
		method             string
		formData           string
		registerBefore     bool
		expectedStatusCode int
		expectedBody       string
	}{
		{
			name:               "Method not allowed",
			method:             http.MethodGet,
			formData:           "",
			registerBefore:     false,
			expectedStatusCode: 405,
			expectedBody:       "Method not allowed\n",
		},
		{
			name:               "Invalid credentials",
			method:             http.MethodPost,
			formData:           "username=doesnot&password=exist",
			registerBefore:     false,
			expectedStatusCode: 401,
			expectedBody:       "Invalid username or password\n",
		},
		{
			name:               "Successful login",
			method:             http.MethodPost,
			formData:           "username=validuser&password=validpassword",
			registerBefore:     true,
			expectedStatusCode: 200,
			expectedBody:       "User logged in successfully",
		},
	}

	initialiseJwks()
	registerUser()

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			request := httptest.NewRequest(scenario.method, "/login", strings.NewReader(scenario.formData))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()
			login(rr, request)
			assert.Equal(t, scenario.expectedStatusCode, rr.Code)
			assert.Equal(t, scenario.expectedBody, rr.Body.String())
		})
	}
}

func Test_UserAccessToProtectedResource(t *testing.T) {
	scenarios := []struct {
		name               string
		method             string
		loginBefore        bool
		expectedStatusCode int
		expectedBody       string
	}{
		{
			name:               "Method not allowed",
			method:             http.MethodGet,
			loginBefore:        true,
			expectedStatusCode: 405,
			expectedBody:       "Method not allowed\n",
		},
		{
			name:               "Unauthorized",
			method:             http.MethodPost,
			expectedStatusCode: 401,
			loginBefore:        false,
			expectedBody:       "Unauthorized\n",
		},
		{
			name:               "Authorized",
			method:             http.MethodPost,
			expectedStatusCode: 200,
			loginBefore:        true,
			expectedBody:       "Welcome, validuser!",
		},
	}

	initialiseJwks()
	registerUser()

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		jwks, _ := jwkSet.JSONPublic(r.Context())
		_, _ = w.Write(jwks)
	}))
	defer testServer.Close()
	_ = os.Setenv("JWKS_BASE_URL", testServer.URL)
	log.Infof("JWKS_BASE_URL: %s ", testServer.URL)

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			request := httptest.NewRequest(scenario.method, "/protected", nil)
			if scenario.loginBefore {
				authHeader, csrfToken := loginUser(t)
				request.Header.Set(authorizationHeader, authHeader)
				request.Header.Set("X-CSRF-Token", csrfToken)
			}
			rr := httptest.NewRecorder()
			withAuth(protected)(rr, request)
			assert.Equal(t, scenario.expectedStatusCode, rr.Code)
			assert.Equal(t, scenario.expectedBody, rr.Body.String())
		})
	}
}

func registerUser() {
	log.Debugf("Registering test user...")
	request := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader("username=validuser&password=validpassword"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	register(rr, request)
}

func loginUser(t *testing.T) (string, string) {
	log.Debugf("Logging in test user...")
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("username=validuser&password=validpassword"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	login(rr, request)
	assert.Equal(t, 200, rr.Code)
	authHeader := rr.Header().Get(authorizationHeader)
	csrfToken := getCookieValue(CsrfToken, rr)
	log.Debugf("Retrieved csrf_token [%v] and authorization header [%v] from request", csrfToken, authHeader)
	return authHeader, csrfToken
}

func getCookieValue(cookieName string, rr *httptest.ResponseRecorder) string {
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == cookieName {
			return cookie.Value
		}
	}
	return ""
}
