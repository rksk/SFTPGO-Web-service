package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// --- Global Variables (Environment Configuration) ---

var (
	ClientID       = os.Getenv("CLIENT_ID")
	ClientSecret   = os.Getenv("CLIENT_SECRET")
	IdPBasePath    = os.Getenv("IDP_BASE_PATH")
	FetchFolderAPI = os.Getenv("FETCH_FOLDER_API")
	AdminTokenURL  = os.Getenv("ADMIN_TOKEN_URL")
	AdminUser      = os.Getenv("ADMIN_USER")
	AdminKey       = os.Getenv("ADMIN_KEY")
	SftpgoFolders  = os.Getenv("SFTPGO_FOLDERS")
	FolderPath     = os.Getenv("FOLDER_PATH")
	CheckRole      = os.Getenv("CHECK_ROLE")
	DIRPath        = os.Getenv("DIR_PATH")
	SCIMScope      = os.Getenv("SCIM_SCOPE")
)

// --- Type Definitions ---

// SFTPGoUser represents a user object from SFTPGo for pre-login hook
type SFTPGoUser struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
}

// UserVirtualFolder represents a virtual folder for a user in SFTPGo
type UserVirtualFolder struct {
	Name        string `json:"name"`
	VirtualPath string `json:"virtual_path"`
}

// MinimalSFTPGoUser represents the minimal SFTPGo user structure for the hook response
type MinimalSFTPGoUser struct {
	Username       string              `json:"username"`
	HomeDir        string              `json:"home_dir"`
	Permissions    map[string][]string `json:"permissions"`
	Status         int                 `json:"status"`
	VirtualFolders []UserVirtualFolder `json:"virtual_folders,omitempty"`
}

// TokenResponse represents the structure of an OAuth2 token response (used for IdP and SFTPGo admin tokens)
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

// AsgardeoUser represents the relevant fields of an Asgardeo user from SCIM
type AsgardeoUser struct {
	UserName   string `json:"userName"`
	Wso2Schema struct {
		UserRole string `json:"UserRole"`
	} `json:"urn:scim:wso2:schema"`
	CustomUser struct {
		SftpAdminFolder string `json:"sftp_admin_folder"`
	} `json:"urn:scim:schemas:extension:custom:User"`
}

// KeyIntRequest represents the incoming request from the SFTPGo client for keyboard-interactive auth.
type KeyIntRequest struct {
	RequestID string   `json:"request_id"`
	Step      int      `json:"step"`
	IP        string   `json:"ip"`
	Username  string   `json:"username"` // Updated to "username" as per user's instruction
	Answers   []string `json:"answers"`
}

// KeyIntResponse represents the response sent back to the SFTPGo client for keyboard-interactive auth.
type KeyIntResponse struct {
	AuthResult    int      `json:"auth_result"` // 1 for success, -1 for failure, 0 for incomplete
	Instruction   string   `json:"instruction"`
	Questions     []string `json:"questions"`
	CheckPassword int      `json:"check_password"` // SFTPGo specific: 1 to check password, 0 otherwise
	Echos         []bool   `json:"echos"`          // true for echo, false for no echo (e.g., password)
}

// RequiredParam represents a detailed parameter required by an authenticator, found in metadata.params.
type RequiredParam struct {
	ParamName      string `json:"param"`        // Matches "param" in JSON
	ParamType      string `json:"type"`         // Matches "type" in JSON
	IsConfidential bool   `json:"confidential"` // Matches "confidential" in JSON
	DisplayName    string `json:"displayName"`  // Matches "displayName" in JSON
	Order          int    `json:"order"`        // Matches "order" in JSON
	I18nKey        string `json:"i18nKey"`      // Matches "i18nKey" in JSON
}

// AuthenticatorMetadata represents the metadata section of an authenticator, containing detailed parameters.
type AuthenticatorMetadata struct {
	I18nKey    string          `json:"i18nKey"`
	PromptType string          `json:"promptType"`
	Params     []RequiredParam `json:"params"` // This now correctly maps to the array of objects
}

// Authenticator represents an authentication method returned by the IdP.
type Authenticator struct {
	AuthenticatorID string                `json:"authenticatorId"`
	DisplayName     string                `json:"authenticator"`
	Metadata        AuthenticatorMetadata `json:"metadata"`       // Added to capture the nested metadata
	RequiredParams  []string              `json:"requiredParams"` // Changed to []string to match JSON's array of strings
	PromptType      string                `json:"promptType"`     // Keep this for top-level prompt type
}

// NextStep represents the next step in the authentication flow from IdP.
type NextStep struct {
	StepType       string          `json:"stepType"` // e.g., "AUTHENTICATION", "COMPLETED"
	Authenticators []Authenticator `json:"authenticators"`
}

// IdPResponse represents the top-level response from the IdP's authentication endpoint.
type IdPResponse struct {
	FlowStatus        string                 `json:"flowStatus"`        // e.g., "INCOMPLETE", "COMPLETED", "FAILED"
	NextStep          *NextStep              `json:"nextStep"`          // Pointer to NextStep, can be nil
	AuthorizationCode string                 `json:"authorizationCode"` // Present on completion
	AuthData          map[string]interface{} `json:"authData"`          // Alternative for authorizationCode
	Error             string                 `json:"error"`             // Error message from IdP
}

// sessionData stores state for each ongoing authentication flow for key-int.
type sessionData struct {
	flowID          string
	nextStep        *NextStep // Store the entire nextStep from IdP for dynamic handling
	currentStepType string    // To keep track of the current step type (e.g., "AUTHENTICATION", "CHALLENGE")
}

// CustomerInfo represents the 200/201 response structure for the subscription hook.
type CustomerInfo struct {
	IsValidCustomer bool     `json:"isValidCustomer"`
	ProjectKeys     []string `json:"projectKeys"`
}

// FolderResponse represents the successful JSON response structure for folder APIs.
type FolderResponse struct {
	IsValidCustomer bool     `json:"isValidCustomer"`
	ProjectKeys     []string `json:"projectKeys"`
}

// ErrorMessage represents the 400/500 response structure for API errors.
type ErrorMessage struct {
	Message string `json:"message"`
}

// --- Session Cache for Key-Interactive Authentication ---

var (
	sessionCache = make(map[string]sessionData)
	cacheMutex   = &sync.Mutex{}
)

// --- Dummy Data Setup (for subscription hook) ---

// Define specific email addresses that will trigger different responses
const (
	email200_1 = "customer1@example.com"
	email200_2 = "customer2@example.com"
	email200_3 = "customer3@example.com"
	email200_4 = "customer4@example.com"
	email200_5 = "customer5@example.com" // 5 emails for 200

	email201_1 = "newuser1@example.com"
	email201_2 = "newuser2@example.com"
	email201_3 = "newuser3@example.com" // 3 emails for 201

	email500_1 = "error@example.com"             // 1 email for 500
	email400_1 = "contact.not.found@example.com" // 1 email for 400 (specific email)
)

// --- Utility Functions ---

// sanitizeUsername replaces special characters in a username with underscores.
func sanitizeUsername(u string) string {
	log.Printf("Sanitizing username: %s", u)
	safe := strings.ReplaceAll(u, "@", "_")
	safe = strings.ReplaceAll(safe, ".", "_")
	safe = strings.ReplaceAll(safe, "/", "_")
	safe = strings.ReplaceAll(safe, "+", "_")
	log.Printf("Sanitized username: %s -> %s", u, safe)
	return safe
}

// postJSON sends a JSON payload to the specified URL and returns the response body.
func postJSON(client *http.Client, url string, payload interface{}) ([]byte, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON payload: %w", err)
	}
	log.Printf("Sending POST to %s with payload: %s", url, string(b))

	res, err := client.Post(url, "application/json", bytes.NewBuffer(b))
	if err != nil {
		return nil, fmt.Errorf("failed to send POST request: %w", err)
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// IdP might return 4xx/5xx for authentication failures, which we need to parse as IdPResponse
	// So, we don't return error immediately on >= 400 status.
	// The caller will unmarshal body and check IdPResponse.FlowStatus/Error.
	if res.StatusCode >= 400 {
		log.Printf("Received HTTP error %d from %s: %s", res.StatusCode, url, string(body))
	} else {
		log.Printf("Received HTTP code %d from %s: %s", res.StatusCode, url, string(body))
	}

	return body, nil
}

// generatePromptFromAuthenticators dynamically creates the client-facing prompt based on IdP authenticators.
func generatePromptFromAuthenticators(authenticators []Authenticator) (instruction string, questions []string, echos []bool) {
	if len(authenticators) == 0 {
		return "No authentication methods available.", []string{}, []bool{}
	}

	if len(authenticators) == 1 {
		// If only one authenticator, directly prompt for its required parameters
		auth := authenticators[0]
		instruction = fmt.Sprintf("Enter your %s details:", auth.DisplayName)
		// Use auth.Metadata.Params for detailed parameter information
		for _, param := range auth.Metadata.Params {
			questions = append(questions, fmt.Sprintf("%s:", param.DisplayName)) // Use DisplayName for the prompt
			echos = append(echos, !param.IsConfidential)
		}
		if len(questions) == 0 {
			// If no required params, it might be a selection step or a "press enter to proceed"
			instruction = fmt.Sprintf("Press enter to proceed with %s.", auth.DisplayName)
			questions = append(questions, "")
			echos = append(echos, true)
		}
	} else {
		// If multiple authenticators, prompt for selection
		instruction = "Select an authentication method:"
		selectionPrompt := ""
		for i, auth := range authenticators {
			selectionPrompt += fmt.Sprintf("[%d] %s\n", i+1, auth.DisplayName)
		}
		selectionPrompt += "Enter selection:" // Changed prompt for clarity
		questions = append(questions, selectionPrompt)
		echos = append(echos, true) // Echo the selection
	}
	return instruction, questions, echos
}

// --- IdP Interaction Functions ---

// getBearerToken obtains an OAuth2 bearer token using client credentials grant.
func getBearerToken() (string, error) {
	log.Println("Attempting to obtain OAuth2 bearer token...")
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", ClientID)
	data.Set("client_secret", ClientSecret)
	data.Set("scope", SCIMScope)

	var TokenURL string = IdPBasePath + "/oauth2/token"
	req, err := http.NewRequest("POST", TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		log.Printf("ERROR: Failed to create token request: %v", err)
		return "", fmt.Errorf("error creating token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	log.Printf("Sending token request to %s", TokenURL)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("ERROR: Failed to send token request to %s: %v", TokenURL, err)
		return "", fmt.Errorf("error sending token request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("ERROR: Token request failed with status %d, body: %s", resp.StatusCode, body)
		return "", fmt.Errorf("token request failed: status %d, body: %s", resp.StatusCode, body)
	}

	var tr TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		log.Printf("ERROR: Failed to parse token response: %v", err)
		return "", fmt.Errorf("failed to parse token response: %v", err)
	}
	log.Println("Successfully obtained OAuth2 bearer token.")
	return tr.AccessToken, nil
}

// getAsgardeoUser fetches user details from Asgardeo via SCIM API.
func getAsgardeoUser(username, token string) (*AsgardeoUser, error) {
	log.Printf("Fetching Asgardeo user for username: %s", username)
	asgUser := username
	if !strings.Contains(username, "/") {
		asgUser = "DEFAULT/" + username
		log.Printf("Prepended 'DEFAULT/' to username for SCIM query: %s", asgUser)
	}
	filter := fmt.Sprintf(`userName eq "%s"`, asgUser)
	params := url.Values{}
	params.Set("filter", filter)

	var SCIMBaseURL string = IdPBasePath + "/scim2/Users"
	scimURL := fmt.Sprintf("%s?%s", SCIMBaseURL, params.Encode())

	req, err := http.NewRequest("GET", scimURL, nil)
	if err != nil {
		log.Printf("ERROR: Failed to create SCIM request for user %s: %v", username, err)
		return nil, fmt.Errorf("SCIM request creation failed: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	log.Printf("Sending SCIM request to %s", scimURL)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("ERROR: SCIM request failed for user %s: %v", username, err)
		return nil, fmt.Errorf("SCIM request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("ERROR: SCIM request failed for user %s: status %d, body: %s", username, resp.StatusCode, body)
		return nil, fmt.Errorf("SCIM request failed: status %d, body: %s", resp.StatusCode, body)
	}

	var result struct {
		TotalResults int            `json:"totalResults"`
		Resources    []AsgardeoUser `json:"Resources"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("ERROR: Failed to parse SCIM response for user %s: %v", username, err)
		return nil, fmt.Errorf("failed to parse SCIM response: %v", err)
	}
	if result.TotalResults < 1 {
		log.Printf("WARN: User '%s' not found in Asgardeo SCIM results.", username)
		return nil, fmt.Errorf("user not found in Asgardeo")
	}
	log.Printf("Successfully fetched Asgardeo user: %s", result.Resources[0].UserName)
	return &result.Resources[0], nil
}

// getFlowID initiates an authentication flow with the IdP and retrieves the flowId.
func getFlowID(client *http.Client) (string, error) {
	url := IdPBasePath + "/oauth2/authorize/"
	// The redirect_uri and scope here are placeholders/examples.
	// Ensure they match your IdP application configuration.
	form := "client_id=" + ClientID + "&client_secret=" + ClientSecret + "&response_type=code&redirect_uri=http://sftpdemo.com:8080/web/oidc/redirect&scope=openid&response_mode=direct"
	req, err := http.NewRequest("POST", url, bytes.NewBufferString(form))
	if err != nil {
		return "", fmt.Errorf("failed to create flow ID request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	log.Printf("Requesting flow ID from %s with form: %s", url, form)

	res, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send flow ID request: %w", err)
	}
	defer res.Body.Close()

	b, _ := ioutil.ReadAll(res.Body)
	if res.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP error %d getting flow ID: %s", res.StatusCode, string(b))
	} else {
		log.Printf("Successfully obtained flow ID with payload: %s", string(b))
	}

	if err != nil {
		return "", fmt.Errorf("failed to read flow ID response body: %w", err)
	}

	var fm struct{ FlowId string }
	if err := json.Unmarshal(b, &fm); err != nil {
		return "", fmt.Errorf("failed to unmarshal flow ID response: %w", err)
	}
	log.Printf("Successfully obtained flow ID: %s", fm.FlowId)
	return fm.FlowId, nil
}

// --- SFTPGo Administration Functions ---

// getSftpgoAdminToken obtains an admin token for SFTPGo API interactions.
func getSftpgoAdminToken() (string, error) {
	log.Println("Attempting to obtain SFTPGo admin token...")
	req, err := http.NewRequest("GET", AdminTokenURL, nil)
	if err != nil {
		log.Printf("ERROR: Failed to create SFTPGo admin token request: %v", err)
		return "", fmt.Errorf("error creating SFTPGo token request: %v", err)
	}
	req.SetBasicAuth(AdminUser, AdminKey)
	log.Printf("Sending SFTPGo admin token request to %s", AdminTokenURL)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("ERROR: Failed to send SFTPGo admin token request to %s: %v", AdminTokenURL, err)
		return "", fmt.Errorf("error sending SFTPGo token request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("ERROR: SFTPGo admin token request failed: status %d, body: %s", resp.StatusCode, body)
		return "", fmt.Errorf("SFTPGo token request failed: status %d, body: %s", resp.StatusCode, body)
	}
	var tr TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		log.Printf("ERROR: Failed to parse SFTPGo admin token response: %v", err)
		return "", fmt.Errorf("failed to parse SFTPGo token response: %v", err)
	}
	log.Println("Successfully obtained SFTPGo admin token.")
	return tr.AccessToken, nil
}

// checkFolderExists checks if a given folder exists in SFTPGo.
func checkFolderExists(name, token string) (bool, error) {
	log.Printf("Checking if SFTPGo folder '%s' exists.", name)
	endpoint := SftpgoFolders + "/" + name
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		log.Printf("ERROR: Failed to create folder check request for '%s': %v", name, err)
		return false, fmt.Errorf("error creating folder check request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	log.Printf("Sending SFTPGo folder check request to %s", endpoint)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("ERROR: Failed to send folder check request for '%s': %v", name, err)
		return false, fmt.Errorf("error sending folder check request: %v", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		log.Printf("SFTPGo folder '%s' exists.", name)
		return true, nil
	case http.StatusNotFound:
		log.Printf("SFTPGo folder '%s' does not exist.", name)
		return false, nil
	default:
		body, _ := io.ReadAll(resp.Body)
		log.Printf("ERROR: Unexpected status %d when checking folder '%s': %s", resp.StatusCode, name, body)
		return false, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, body)
	}
}

// createFolder creates a new folder in SFTPGo.
func createFolder(name, token, user string) error {
	log.Printf("Attempting to create SFTPGo folder '%s' for user '%s'.", name, user)
	path := filepath.Join(FolderPath, name)
	// log.Printf("Creating local directory path: %s", path)
	// if err := os.MkdirAll(path, 0755); err != nil {
	//  log.Printf("ERROR: Failed to create local directory %s: %v", path, err)
	//  return fmt.Errorf("failed to create local directory: %v", err)
	// }

	payload := map[string]interface{}{
		"name":         name,
		"mapped_path":  path,
		"virtual_path": "/" + name,
		"description":  fmt.Sprintf("Created via API for user %s", user),
		"users":        []string{user},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		log.Printf("ERROR: Failed to marshal create folder payload for '%s': %v", name, err)
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	req, err := http.NewRequest("POST", SftpgoFolders, strings.NewReader(string(b)))
	if err != nil {
		log.Printf("ERROR: Failed to create SFTPGo folder creation request for '%s': %v", name, err)
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	log.Printf("Sending SFTPGo folder creation request to %s with payload: %s", SftpgoFolders, string(b))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("ERROR: Failed to send SFTPGo folder creation request for '%s': %v", name, err)
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("ERROR: SFTPGo folder creation failed for '%s': status %d, body: %s", name, resp.StatusCode, body)
		return fmt.Errorf("folder creation failed: %d %s", resp.StatusCode, body)
	}
	log.Printf("Successfully created SFTPGo folder '%s' for user '%s'.", name, user)
	return nil
}

// provisionUserFolders ensures necessary folders exist for a user in SFTPGo.
func provisionUserFolders(user string, folders []string) error {
	log.Printf("Starting folder provisioning for user: %s. Folders to check/create: %v", user, folders)
	token, err := getSftpgoAdminToken()
	if err != nil {
		log.Printf("ERROR: Failed to get SFTPGo admin token for provisioning user '%s': %v", user, err)
		return fmt.Errorf("failed to get SFTPGo admin token: %v", err)
	}

	for _, f := range folders {
		log.Printf("Processing folder '%s' for user '%s'.", f, user)
		exists, err := checkFolderExists(f, token)
		if err != nil {
			log.Printf("WARN: Error checking existence of folder '%s' for user '%s': %v. Skipping.", f, user, err)
			continue
		}
		if !exists {
			log.Printf("Folder '%s' does not exist. Attempting to create it for user '%s'.", f, user)
			if err := createFolder(f, token, user); err != nil {
				log.Printf("ERROR: Failed to create folder '%s' for user '%s': %v", f, user, err)
			} else {
				log.Printf("Successfully created folder '%s' for user '%s'.", f, user)
			}
		} else {
			log.Printf("Folder '%s' already exists for user '%s'. No action needed.", f, user)
		}
	}
	log.Printf("Finished folder provisioning for user: %s.", user)
	return nil
}

// getAllFolders fetches all existing SFTPGo folders.
func getAllFolders(token string) ([]UserVirtualFolder, error) {
	log.Println("Fetching all existing SFTPGo folders.")
	endpoint := SftpgoFolders // + "?limit=5000"
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		log.Printf("ERROR: Failed to create request to get all SFTPGo folders: %v", err)
		return nil, fmt.Errorf("error creating folders list request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	log.Printf("Sending request to get all SFTPGo folders from %s", endpoint)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("ERROR: Failed to send request to get all SFTPGo folders: %v", err)
		return nil, fmt.Errorf("error sending folders list request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("ERROR: Request to get all SFTPGo folders failed: status %d, body: %s", resp.StatusCode, body)
		return nil, fmt.Errorf("folders list request failed: status %d, body: %s", resp.StatusCode, body)
	}
	var folders []struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&folders); err != nil {
		log.Printf("ERROR: Failed to decode all SFTPGo folders list: %v", err)
		return nil, fmt.Errorf("failed to decode folders list: %v", err)
	}
	result := make([]UserVirtualFolder, len(folders))
	for i, f := range folders {
		result[i] = UserVirtualFolder{Name: f.Name, VirtualPath: "/" + f.Name}
	}
	log.Printf("Successfully fetched %d SFTPGo folders.", len(result))
	return result, nil
}

// getUserFolderList retrieves a custom folder list for a user from an external API.
func getUserFolderList(username string) []string {
	log.Printf("Attempting to retrieve custom folder list for user: %s", username)
	api := fmt.Sprintf(FetchFolderAPI,
		url.QueryEscape(username),
	)
	req, err := http.NewRequest("GET", api, nil)
	if err != nil {
		log.Printf("ERROR: Folder list request creation error for user %s: %v", username, err)
		return nil
	}
	req.Header.Set("Accept", "application/json")
	log.Printf("Sending request to custom folder API: %s", api)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("ERROR: Failed to send folder list request for user %s: %v", username, err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		// Attempt to decode as an error message
		var errorResp ErrorMessage
		if unmarshalErr := json.Unmarshal(body, &errorResp); unmarshalErr == nil && errorResp.Message != "" {
			log.Printf("WARN: Folder list API for user %s returned status %d, message: %s", username, resp.StatusCode, errorResp.Message)
		} else {
			log.Printf("WARN: Folder list API for user %s returned status %d, body: %s", username, resp.StatusCode, body)
		}
		return nil
	}

	var folderResp FolderResponse
	if err := json.NewDecoder(resp.Body).Decode(&folderResp); err != nil {
		log.Printf("ERROR: Failed to decode custom folder list for user %s: %v", username, err)
		return nil
	}

	if !folderResp.IsValidCustomer {
		log.Printf("INFO: User %s is not a valid customer. No project keys returned.", username)
		return nil // Or return an empty slice if that's desired for invalid customers
	}

	log.Printf("Successfully retrieved %d custom folders for user %s.", len(folderResp.ProjectKeys), username)

	// Convert all project keys to lowercase
	lowercaseProjectKeys := make([]string, len(folderResp.ProjectKeys))
	for i, key := range folderResp.ProjectKeys {
		lowercaseProjectKeys[i] = strings.ToLower(key)
	}

	return lowercaseProjectKeys
}

// --- HTTP Handlers ---

// preLoginHook handles SFTPGo's pre-login hook to provision users and folders.
func preLoginHook(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received pre-login hook request from %s for method %s", r.RemoteAddr, r.Method)

	if r.Method != http.MethodPost {
		log.Printf("WARN: Method not allowed. Expected POST, got %s.", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var u SFTPGoUser
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		log.Printf("ERROR: Invalid payload received in pre-login hook: %v", err)
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}
	log.Printf("Decoded SFTPGo user payload: %+v", u)

	// TODO: Add project rescan for existing users
	if u.ID != 0 {
		log.Printf("INFO: SFTPGo user ID is not 0 (%d). Returning HTTP 204.", u.ID)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	user := u.Username
	if user == "" {
		log.Printf("ERROR: No username provided in pre-login hook payload.")
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	log.Printf("Processing pre-login hook for username: %s", user)

	token, err := getBearerToken()
	if err != nil {
		log.Printf("ERROR: Failed to get bearer token for user %s: %v", user, err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	log.Println("Bearer token obtained successfully.")

	asg, err := getAsgardeoUser(user, token)
	if err != nil {
		log.Printf("ERROR: Failed to get Asgardeo user '%s': %v", user, err)
		// http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}
	log.Printf("Asgardeo user details fetched for %s: %+v", user, asg)

	role := strings.ToLower(asg.Wso2Schema.UserRole)
	isInternalUser := role == CheckRole
	log.Printf("User '%s' role: '%s'. Is Internal user ('%s')? %t", user, role, CheckRole, isInternalUser)

	var home string
	var folders []string
	perms := make(map[string][]string)
	var vfs []UserVirtualFolder

	if isInternalUser {
		log.Printf("Configuring SFTPGo user '%s' as internal user.", user)
		home = FolderPath
		log.Printf("Setting home directory to: %s", home)

		sftpgoToken, err := getSftpgoAdminToken()
		if err != nil {
			log.Printf("ERROR: Failed to get SFTPGo token for internal user '%s' folder configuration: %v", user, err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		log.Println("SFTPGo admin token obtained for system user.")

		allFolders, err := getAllFolders(sftpgoToken)
		if err != nil {
			log.Printf("ERROR: Failed to get all SFTPGo folders for internal user '%s': %v", user, err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		vfs = allFolders
		log.Printf("Assigned all %d SFTPGo folders as virtual folders for internal user '%s'.", len(allFolders), user)

		perms["/"] = []string{"list"}
		for _, f := range allFolders {
			perms[f.VirtualPath] = []string{"upload", "list", "download", "create_dirs", "delete"}
		}
		log.Printf("Assigned full permissions to all virtual folders for internal user '%s'.", user)

	} else {
		log.Printf("Configuring SFTPGo user '%s' as external user.", user)
		// home = filepath.Join(DIRPath, sanitizeUsername(user))
		// log.Printf("Setting home directory to: %s", home)
		// if err := os.MkdirAll(home, 0755); err != nil {
		// 	log.Printf("ERROR: Failed to create home directory %s for user %s: %v", home, user, err)
		// 	// Decide if this should be a fatal error or just logged
		// } else {
		// 	log.Printf("Ensured home directory %s exists for user %s.", home, user)
		// }

		folders = getUserFolderList(user)
		if len(folders) == 0 {
			log.Printf("No customer folders allowed for user '%s'.", user)
			if asg.CustomUser.SftpAdminFolder != "" {
				folders = []string{asg.CustomUser.SftpAdminFolder}
				log.Printf("Using 'sftp_admin_folder' from Asgardeo: %v", folders)
				perms["/"] = []string{"upload", "list", "download", "create_dirs", "delete"} // Default permissions for root
			} else {
				log.Printf("Skip provisioning the user '%s'.", user)
				return
			}
		} else {
			log.Printf("Custom folders fetched for user '%s': %v", user, folders)
			perms["/"] = []string{"list"} // Default permissions for root
		}

		if err := provisionUserFolders(user, folders); err != nil {
			log.Printf("ERROR: Failed to provision folders for user '%s': %v", user, err)
		} else {
			log.Printf("Folders provisioned successfully for user '%s'.", user)
		}

		for _, f := range folders {
			p := "/" + f
			perms[p] = []string{"upload", "list", "download", "create_dirs", "delete"}
			vfs = append(vfs, UserVirtualFolder{Name: f, VirtualPath: p})
		}
		log.Printf("Assigned specific permissions and virtual folders for user '%s'. Virtual folders: %+v", user, vfs)
	}

	res := MinimalSFTPGoUser{
		Username:       user,
		HomeDir:        home,
		Permissions:    perms,
		Status:         1, // Assuming active status
		VirtualFolders: vfs,
	}
	log.Printf("Constructed SFTPGo user response for '%s': %+v", user, res)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(res); err != nil {
		log.Printf("ERROR: Failed to encode SFTPGo user response for '%s': %v", user, err)
		// This is a critical error, but response header is already set
	} else {
		log.Printf("Successfully sent SFTPGo user response for '%s'.", user)
	}
}

// keyIntHandler handles the keyboard-interactive authentication flow with the IdP.
func keyIntHandler(w http.ResponseWriter, r *http.Request) {
	var req KeyIntRequest
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("ERROR: Failed to read request body: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		log.Printf("ERROR: Failed to unmarshal request body: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	log.Printf("Received keyIntHandler request: step=%d id=%s user=%s answers=%v", req.Step, req.RequestID, req.Username, req.Answers)

	var resp KeyIntResponse
	client := &http.Client{Timeout: 15 * time.Second}
	idpURL := IdPBasePath + "/oauth2/authn"

	cacheMutex.Lock()
	data, ok := sessionCache[req.RequestID]
	cacheMutex.Unlock()

	// Declare idpRespBytes here so it's accessible throughout the function
	var idpRespBytes []byte

	// Handle initial request (Step 1: SFTPGo client sends username and password)
	// SFTPGo always sends the username in req.Username and the password in req.Answers[0] for the first step.
	// We will use these directly and not re-prompt the user for them.
	if req.Step == 1 {
		username := req.Username

		if username == "" {
			log.Printf("ERROR: Username is missing in initial request for RequestID: %s", req.RequestID)
			resp.AuthResult = -1
			resp.Instruction = "Authentication failed: Username missing."
			goto sendResponse
		}

		// 1. Get the initial flow ID from the IdP
		flow, err := getFlowID(client)
		if err != nil {
			log.Printf("ERROR: Failed to get flow ID for user %s: %v", username, err)
			resp.AuthResult = -1
			resp.Instruction = "Authentication failed: Internal error getting flow ID."
			goto sendResponse
		}

		// 2. Initiate the authentication flow with username and password
		// The username and password are "autofilled" into this payload, as they are provided by SFTPGo.
		primaryAuthPayload := map[string]interface{}{
			"flowId": flow,
			"selectedAuthenticator": map[string]interface{}{
				"authenticatorId": "SWRlbnRpZmllckV4ZWN1dG9yOkxPQ0FM", // Identifier first Authenticator ID for Asgardeo
				"params":          map[string]interface{}{"username": username},
			},
		}

		idpRespBytes, err = postJSON(client, idpURL, primaryAuthPayload)
		if err != nil {
			log.Printf("ERROR: Failed to send primary authentication request for user %s: %v", username, err)
			resp.AuthResult = -1
			resp.Instruction = "Authentication failed: Communication error with IdP."
			goto sendResponse
		}

		var idpResp IdPResponse
		if err := json.Unmarshal(idpRespBytes, &idpResp); err != nil {
			log.Printf("ERROR: Failed to unmarshal IdP response after primary auth for user %s: %v, Response Body: %s", username, err, string(idpRespBytes))
			resp.AuthResult = -1
			resp.Instruction = "Authentication failed: Invalid response from IdP."
			goto sendResponse
		}

		// 3. Process the IdP's response
		if idpResp.FlowStatus == "COMPLETED" {
			log.Printf("Authentication successful for %s (completed in step 1)", username)
			resp.AuthResult = 1
			// No need to store session data as flow is complete
		} else if idpResp.FlowStatus == "INCOMPLETE" && idpResp.NextStep != nil {
			// Store the next step information in the session cache
			cacheMutex.Lock()
			sessionCache[req.RequestID] = sessionData{
				flowID:          flow,
				nextStep:        idpResp.NextStep,
				currentStepType: idpResp.NextStep.StepType,
			}
			cacheMutex.Unlock()

			// Dynamically generate the prompt for the client based on the IdP's next step
			// This will NOT re-prompt for username/password, but for subsequent MFA/challenge steps.
			resp.Instruction, resp.Questions, resp.Echos = generatePromptFromAuthenticators(idpResp.NextStep.Authenticators)
			resp.AuthResult = 0 // Incomplete, client needs to provide more answers
			log.Printf("Authentication incomplete for %s. IdP requires further steps. Instruction: '%s', Questions: %v", username, resp.Instruction, resp.Questions)
		} else {
			// Authentication failed or unexpected flow status
			log.Printf("ERROR: Authentication failed or unexpected IdP flow status for user %s: %s. IdP Error: %s", username, idpResp.FlowStatus, idpResp.Error)
			resp.AuthResult = -1
			if idpResp.Error != "" {
				resp.Instruction = "Authentication failed: " + idpResp.Error
			} else {
				resp.Instruction = "Authentication failed. Please try again."
			}
		}
	} else if ok { // Subsequent steps (req.Step > 1)
		// Retrieve session data
		flow := data.flowID
		currentNextStep := data.nextStep

		if currentNextStep == nil || len(currentNextStep.Authenticators) == 0 {
			log.Printf("ERROR: Invalid session state for request ID %s: No next step or authenticators.", req.RequestID)
			resp.AuthResult = -1
			resp.Instruction = "Authentication session expired or invalid. Please start over."
			goto sendResponse
		}

		var selectedAuthenticator Authenticator
		var authenticatorParams = make(map[string]interface{})
		var err error

		// Determine the selected authenticator and populate its parameters
		if len(currentNextStep.Authenticators) > 1 {
			// User is selecting an authenticator (e.g., from a list of MFA options)
			if len(req.Answers) == 0 {
				log.Printf("ERROR: No authenticator selection provided for request ID %s", req.RequestID)
				resp.AuthResult = -1
				resp.Instruction = "Authentication failed: Please select an option."
				goto sendResponse
			}
			selection, parseErr := strconv.Atoi(req.Answers[0])
			if parseErr != nil || selection < 1 || selection > len(currentNextStep.Authenticators) {
				log.Printf("ERROR: Invalid authenticator selection '%s' for request ID %s", req.Answers[0], req.RequestID)
				resp.AuthResult = -1
				resp.Instruction = "Authentication failed: Invalid selection."
				goto sendResponse
			}
			selectedAuthenticator = currentNextStep.Authenticators[selection-1] // Adjust for 0-based index

			// After selection, the next client request (same req.Step if client resends, or next req.Step)
			// should provide parameters for this selected authenticator.
			// For simplicity in this example, we assume the SFTPGo client will send the selection
			// and then the parameters in the *next* request if needed.
			// If the selected authenticator has required parameters, we need to prompt for them.
			// This means we might need to update the session's `nextStep` to reflect
			// the parameters of the *chosen* authenticator, and then re-prompt.
			if len(selectedAuthenticator.Metadata.Params) > 0 { // Use Metadata.Params here
				// This implies the client needs to be prompted for these params next.
				// We update the session and send the new prompt.
				cacheMutex.Lock()
				sessionCache[req.RequestID] = sessionData{
					flowID:          flow,
					nextStep:        &NextStep{Authenticators: []Authenticator{selectedAuthenticator}}, // Update nextStep to focus on this authenticator
					currentStepType: selectedAuthenticator.PromptType,                                  // Or a more specific type
				}
				cacheMutex.Unlock()

				resp.Instruction, resp.Questions, resp.Echos = generatePromptFromAuthenticators([]Authenticator{selectedAuthenticator})
				resp.AuthResult = 0 // Incomplete, waiting for params
				log.Printf("User %s selected authenticator '%s'. Prompting for its parameters. Instruction: '%s', Questions: %v", req.Username, selectedAuthenticator.DisplayName, resp.Instruction, resp.Questions)
				goto sendResponse // Send the prompt for parameters
			}
			// If no required params, then this selection implicitly completes this step.
			// We proceed to send the payload with just the authenticator ID.
			authenticatorParams = make(map[string]interface{}) // Empty params
		} else {
			// Only one authenticator available, it's implicitly selected.
			// The answers provided in req.Answers are assumed to be for its required parameters.
			selectedAuthenticator = currentNextStep.Authenticators[0]

			if len(req.Answers) != len(selectedAuthenticator.Metadata.Params) { // Use Metadata.Params here
				log.Printf("ERROR: Mismatch in number of answers and required params for authenticator %s. Expected %d, got %d.",
					selectedAuthenticator.DisplayName, len(selectedAuthenticator.Metadata.Params), len(req.Answers))
				resp.AuthResult = -1
				resp.Instruction = "Authentication failed: Missing answers for required fields."
				goto sendResponse
			}
			for i, param := range selectedAuthenticator.Metadata.Params { // Use Metadata.Params here
				authenticatorParams[param.ParamName] = req.Answers[i]
			}
			log.Printf("User %s providing answers for authenticator '%s'. Params: %v", req.Username, selectedAuthenticator.DisplayName, authenticatorParams)
		}

		// Construct the payload for the IdP for the current step
		payload := map[string]interface{}{
			"flowId": flow,
			"selectedAuthenticator": map[string]interface{}{
				"authenticatorId": selectedAuthenticator.AuthenticatorID,
				"params":          authenticatorParams,
			},
		}

		idpRespBytes, err = postJSON(client, idpURL, payload)
		if err != nil {
			log.Printf("ERROR: Authentication step failed for %s: %v", req.Username, err)
			resp.AuthResult = -1
			resp.Instruction = "Authentication failed: Communication error with IdP in subsequent step."
			goto sendResponse
		}

		var idpResp IdPResponse
		if err := json.Unmarshal(idpRespBytes, &idpResp); err != nil {
			log.Printf("ERROR: Failed to unmarshal IdP response in subsequent step for user %s: %v, Response Body: %s", req.Username, err, string(idpRespBytes))
			resp.AuthResult = -1
			resp.Instruction = "Authentication failed: Invalid response from IdP in subsequent step."
			goto sendResponse
		}

		if idpResp.FlowStatus == "SUCCESS_COMPLETED" {
			log.Printf("Authentication successful for %s", req.Username)
			resp.AuthResult = 1
			// Extract authorization code (if needed by SFTPGo, though typically not for key-int)
			if idpResp.AuthorizationCode != "" {
				log.Printf("Authorization Code: %s", idpResp.AuthorizationCode)
			} else if idpResp.AuthData != nil {
				if code, ok := idpResp.AuthData["code"].(string); ok && code != "" {
					log.Printf("Authorization Code (from authData): %s", code)
				}
			}
			// Clean up session cache as flow is complete
			cacheMutex.Lock()
			delete(sessionCache, req.RequestID)
			cacheMutex.Unlock()
		} else if idpResp.FlowStatus == "FAIL_INCOMPLETE" && idpResp.NextStep != nil {
			// Update session with the new next step from IdP
			cacheMutex.Lock()
			sessionCache[req.RequestID] = sessionData{
				flowID:          flow,
				nextStep:        idpResp.NextStep,
				currentStepType: idpResp.NextStep.StepType,
			}
			cacheMutex.Unlock()

			// Dynamically generate the prompt for the client based on the new next step
			resp.Instruction, resp.Questions, resp.Echos = generatePromptFromAuthenticators(idpResp.NextStep.Authenticators)
			resp.AuthResult = 0 // Still incomplete
			log.Printf("Authentication incomplete for %s. IdP requires further steps. Instruction: '%s', Questions: %v", req.Username, resp.Instruction, resp.Questions)
		} else {
			// Authentication failed or unexpected IdP response in a subsequent step
			log.Printf("ERROR: Authentication failed or unexpected IdP response for user %s: %s. IdP Error: %s", req.Username, idpResp.FlowStatus, idpResp.Error)
			resp.AuthResult = -1
			if idpResp.Error != "" {
				resp.Instruction = "Authentication failed: " + idpResp.Error
			} else {
				resp.Instruction = "Authentication failed. Please try again."
			}
		}
	} else {
		// No session data found for subsequent steps or invalid step
		log.Printf("ERROR: Invalid request step %d or no session found for ID %s", req.Step, req.RequestID)
		resp.AuthResult = -1
		resp.Instruction = "Authentication session expired or invalid. Please start over."
	}

sendResponse: // Label for goto statements
	out, err := json.Marshal(resp)
	if err != nil {
		log.Printf("ERROR: Failed to marshal response to client: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	log.Printf("Sending response to client: %s", out)
	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

// subscriptionHandler is a dummy handler for subscription API.
func subscriptionHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received request for /subscription from %s. Path: %s, Query: %s", r.RemoteAddr, r.URL.Path, r.URL.RawQuery)

	// Get the 'email' query parameter
	email := r.URL.Query().Get("email")
	email = strings.ToLower(strings.TrimSpace(email)) // Clean up email for consistency

	w.Header().Set("Content-Type", "application/json")

	// --- Response Logic based on email ---
	switch email {
	case "":
		// Case for missing email query parameter
		log.Printf("ERROR: 'email' query parameter is missing for request from %s", r.RemoteAddr)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorMessage{Message: "Email query parameter is required."})
		return

	case email200_1, email200_2, email200_3, email200_4, email200_5:
		// Emails for HTTP 200 OK
		log.Printf("Responding 200 OK for email: %s", email)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(CustomerInfo{
			IsValidCustomer: true,
			ProjectKeys:     []string{"ABCSUB", "XYZSUB"},
		})
		return

	case email201_1, email201_2, email201_3:
		// Emails for HTTP 201 Created (isValidCustomer: false)
		log.Printf("Responding 201 Created for email: %s", email)
		w.WriteHeader(http.StatusCreated) // Note: 201 is typically for resource creation
		json.NewEncoder(w).Encode(CustomerInfo{
			IsValidCustomer: false,
			ProjectKeys:     []string{},
		})
		return

	case email400_1:
		// Email for HTTP 400 Bad Request (explicit contact not found via email)
		log.Printf("Responding 400 Bad Request (Contact Not Found) for email: %s", email)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorMessage{Message: "Contact not found."})
		return

	case email500_1:
		// Email for HTTP 500 Internal Server Error
		log.Printf("Responding 500 Internal Server Error for email: %s", email)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorMessage{Message: "Error while fetching Contact information."})
		return

	default:
		// Default case for any other email not explicitly listed.
		// Could be 201, 404, or another status depending on desired behavior for unknown contacts.
		// Sticking to 201 isValidCustomer: false, as it's provided in the prompt.
		log.Printf("Responding 201 Created (Default/Unknown) for email: %s", email)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(CustomerInfo{
			IsValidCustomer: false,
			ProjectKeys:     []string{},
		})
		return
	}
}

// --- Main Function ---

func main() {
	// Configure logging output to include date, time, and file name/line number
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.Println("Starting SFTPGo Pre-Login Hook service...")
	log.Printf("Environment Variables Loaded:")
	log.Printf("  CLIENT_ID: %s", ClientID)
	log.Printf("  IDP_BASE_PATH: %s", IdPBasePath)
	log.Printf("  FETCH_FOLDER_API: %s", FetchFolderAPI)
	log.Printf("  ADMIN_TOKEN_URL: %s", AdminTokenURL)
	log.Printf("  ADMIN_USER: %s (first 4 chars)", AdminUser[:4])
	log.Printf("  SFTPGO_FOLDERS: %s", SftpgoFolders)
	log.Printf("  FOLDER_PATH: %s", FolderPath)
	log.Printf("  CHECK_ROLE: %s", CheckRole)
	log.Printf("  DIR_PATH: %s", DIRPath)
	log.Printf("  SCIM_SCOPE: %s", SCIMScope)

	// Basic validation for critical environment variables
	if ClientID == "" || ClientSecret == "" || IdPBasePath == "" || AdminTokenURL == "" || AdminUser == "" || AdminKey == "" || SftpgoFolders == "" || FolderPath == "" || DIRPath == "" || CheckRole == "" || SCIMScope == "" {
		log.Fatal("ERROR: One or more critical environment variables are not set. Please ensure CLIENT_ID, CLIENT_SECRET, IDP_BASE_PATH, ADMIN_TOKEN_URL, ADMIN_USER, ADMIN_KEY, SFTPGO_FOLDERS, FOLDER_PATH, DIR_PATH, CHECK_ROLE, SCIM_SCOPE are configured.")
	}

	http.HandleFunc("/prelogin-hook", preLoginHook)
	http.HandleFunc("/auth-hook", keyIntHandler)
	http.HandleFunc("/subscription-hook", subscriptionHandler) // Only for demo purpose

	log.Println("SFTPGo Pre-Login and Auth Hooks are listening on :9000/prelogin-hook and :9000/auth-hook")
	if err := http.ListenAndServe(":9000", nil); err != nil {
		log.Fatalf("FATAL: Server error: %v", err)
	}
}
