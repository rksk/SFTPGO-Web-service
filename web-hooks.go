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

// SFTPGoUser represents a user object from SFTPGo
type SFTPGoUser struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
}

// UserVirtualFolder represents a virtual folder for a user
type UserVirtualFolder struct {
	Name        string `json:"name"`
	VirtualPath string `json:"virtual_path"`
}

// MinimalSFTPGoUser represents the minimal SFTPGo user structure for the hook
type MinimalSFTPGoUser struct {
	Username       string              `json:"username"`
	HomeDir        string              `json:"home_dir"`
	Permissions    map[string][]string `json:"permissions"`
	Status         int                 `json:"status"`
	VirtualFolders []UserVirtualFolder `json:"virtual_folders,omitempty"`
}

// TokenResponse represents the structure of an OAuth2 token response
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

// AsgardeoUser represents the relevant fields of an Asgardeo user
type AsgardeoUser struct {
	UserName   string `json:"userName"`
	Wso2Schema struct {
		UserRole string `json:"UserRole"`
	} `json:"urn:scim:wso2:schema"`
	CustomUser struct {
		SftpAdminFolder string `json:"sftp_admin_folder"`
	} `json:"urn:scim:schemas:extension:custom:User"`
}

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

func sanitizeUsername(u string) string {
	log.Printf("Sanitizing username: %s", u)
	safe := strings.ReplaceAll(u, "@", "_")
	safe = strings.ReplaceAll(safe, ".", "_")
	safe = strings.ReplaceAll(safe, "/", "_")
	safe = strings.ReplaceAll(safe, "+", "_")
	log.Printf("Sanitized username: %s -> %s", u, safe)
	return safe
}

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

// Define a struct to match the successful JSON response structure
type FolderResponse struct {
	IsValidCustomer bool     `json:"isValidCustomer"`
	ProjectKeys     []string `json:"projectKeys"`
}

// Define a struct to match the error JSON response structure
type ErrorResponse struct {
	Message string `json:"message"`
}

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
		var errorResp ErrorResponse
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
	return folderResp.ProjectKeys
}

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

func createFolder(name, token, user string) error {
	log.Printf("Attempting to create SFTPGo folder '%s' for user '%s'.", name, user)
	path := filepath.Join(FolderPath, name)
	// log.Printf("Creating local directory path: %s", path)
	// if err := os.MkdirAll(path, 0755); err != nil {
	// 	log.Printf("ERROR: Failed to create local directory %s: %v", path, err)
	// 	return fmt.Errorf("failed to create local directory: %v", err)
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
		home = filepath.Join(DIRPath, sanitizeUsername(user))
		log.Printf("Setting home directory to: %s", home)
		if err := os.MkdirAll(home, 0755); err != nil {
			log.Printf("ERROR: Failed to create home directory %s for user %s: %v", home, user, err)
			// Decide if this should be a fatal error or just logged
		} else {
			log.Printf("Ensured home directory %s exists for user %s.", home, user)
		}

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

// KeyIntRequest represents the incoming request from the client.
type KeyIntRequest struct {
	RequestID string   `json:"request_id"`
	Step      int      `json:"step"`
	IP        string   `json:"ip"`
	Username  string   `json:"user"`
	Answers   []string `json:"answers"`
}

// KeyIntResponse represents the response sent back to the client.
type KeyIntResponse struct {
	AuthResult    int      `json:"auth_result"` // 1 for success, -1 for failure, 0 for incomplete
	Instruction   string   `json:"instruction"`
	Questions     []string `json:"questions"`
	CheckPassword int      `json:"check_password"`
	Echos         []bool   `json:"echos"` // true for echo, false for no echo (e.g., password)
}

// --- IdP API Response Structs (to dynamically parse responses from the Identity Provider) ---

// RequiredParam represents a parameter required by an authenticator.
type RequiredParam struct {
	ParamName      string `json:"paramName"`
	ParamType      string `json:"paramType"`
	IsConfidential bool   `json:"isConfidential"`
}

// Authenticator represents an authentication method returned by the IdP.
type Authenticator struct {
	AuthenticatorID string          `json:"authenticatorId"`
	DisplayName     string          `json:"displayName"`
	RequiredParams  []RequiredParam `json:"requiredParams"`
	PromptType      string          `json:"promptType"` // e.g., "TEXT", "PASSWORD", "SELECT"
}

// NextStep represents the next step in the authentication flow.
type NextStep struct {
	StepType       string          `json:"stepType"` // e.g., "AUTHENTICATION", "COMPLETED"
	Authenticators []Authenticator `json:"authenticators"`
}

// IdPResponse represents the top-level response from the IdP.
type IdPResponse struct {
	FlowStatus        string                 `json:"flowStatus"`        // e.g., "INCOMPLETE", "COMPLETED", "FAILED"
	NextStep          *NextStep              `json:"nextStep"`          // Pointer to NextStep, can be nil
	AuthorizationCode string                 `json:"authorizationCode"` // Present on completion
	AuthData          map[string]interface{} `json:"authData"`          // Alternative for authorizationCode
	Error             string                 `json:"error"`             // Error message from IdP
}

// --- Session Management ---

// sessionData stores state for each ongoing authentication flow.
type sessionData struct {
	flowID          string
	nextStep        *NextStep // Store the entire nextStep from IdP for dynamic handling
	currentStepType string    // To keep track of the current step type (e.g., "AUTHENTICATION", "CHALLENGE")
}

var (
	sessionCache = make(map[string]sessionData)
	cacheMutex   = &sync.Mutex{}
)

// getFlowID initiates an authentication flow and retrieves the flowId.
func getFlowID(client *http.Client) (string, error) {
	url := IdPBasePath + "/oauth2/authorize/"
	form := "client_id=" + ClientID + "&client_secret=" + ClientSecret + "&response_type=code&redirect_uri=http://sftpdemo.com:8080/web/oidc/redirect&scope=openid&response_mode=direct"
	req, err := http.NewRequest("POST", url, bytes.NewBufferString(form))
	if err != nil {
		return "", fmt.Errorf("failed to create flow ID request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send flow ID request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode >= 400 {
		body, _ := ioutil.ReadAll(res.Body)
		return "", fmt.Errorf("HTTP error %d getting flow ID: %s", res.StatusCode, string(body))
	}

	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read flow ID response body: %w", err)
	}

	var fm struct{ FlowId string }
	if err := json.Unmarshal(b, &fm); err != nil {
		return "", fmt.Errorf("failed to unmarshal flow ID response: %w", err)
	}
	return fm.FlowId, nil
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

	if res.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP error %d: %s", res.StatusCode, string(body))
	}

	return body, nil
}

// generatePromptFromAuthenticators dynamically creates the client-facing prompt.
func generatePromptFromAuthenticators(authenticators []Authenticator) (instruction string, questions []string, echos []bool) {
	if len(authenticators) == 0 {
		return "No authentication methods available.", []string{}, []bool{}
	}

	if len(authenticators) == 1 {
		// If only one authenticator, directly prompt for its required parameters
		auth := authenticators[0]
		instruction = fmt.Sprintf("Enter your %s details:", auth.DisplayName)
		for _, param := range auth.RequiredParams {
			questions = append(questions, fmt.Sprintf("%s:", param.ParamName))
			echos = append(echos, !param.IsConfidential)
		}
		if len(questions) == 0 {
			// If no required params, it might be a selection step
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
		selectionPrompt += "Enter:"
		questions = append(questions, selectionPrompt)
		echos = append(echos, true) // Echo the selection
	}
	return instruction, questions, echos
}

// --- Main Handler Function ---

// keyIntHandler handles the interaction with the client and the IdP.
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
	log.Printf("recv step=%d id=%s user=%s answers=%v", req.Step, req.RequestID, req.Username, req.Answers)

	var resp KeyIntResponse
	client := &http.Client{Timeout: 15 * time.Second}
	idpURL := IdPBasePath + "/oauth2/authn"

	cacheMutex.Lock()
	data, ok := sessionCache[req.RequestID]
	cacheMutex.Unlock()

	// Declare respBody here so it's accessible throughout the function
	var respBody []byte

	// Handle initial request (Step 1: Get Username/Password)
	if req.Step == 1 {
		resp.Instruction = "Enter your username and password:"
		resp.Questions = []string{"Username:", "Password:"}
		resp.Echos = []bool{true, false} // Echo username, hide password
		// No IdP call yet, just prompt for initial credentials
	} else if req.Step == 2 {
		// Step 2: Send username/password to IdP and get next step
		username := req.Username
		password := ""
		if len(req.Answers) > 1 {
			username = req.Answers[0] // Assuming answers[0] is username, answers[1] is password
			password = req.Answers[1]
		} else if len(req.Answers) > 0 {
			// Fallback if client only sends password in answers[0] for some reason
			password = req.Answers[0]
		}

		flow, err := getFlowID(client)
		if err != nil {
			log.Printf("ERROR: Failed to get flow ID: %v", err)
			resp.AuthResult = -1
			goto sendResponse // Use goto for early exit on error
		}

		primaryAuthPayload := map[string]interface{}{
			"flowId": flow,
			"selectedAuthenticator": map[string]interface{}{
				"authenticatorId": "QmFzaWNBdXRoZW50aWNhdG9yOkxPQ0FM", // Basic Authenticator ID
				"params":          map[string]interface{}{"username": username, "password": password},
			},
		}

		respBody, err := postJSON(client, idpURL, primaryAuthPayload)
		if err != nil {
			log.Printf("ERROR: Primary authentication failed: %v", err)
			resp.AuthResult = -1
			goto sendResponse
		}

		var idpResp IdPResponse
		if err := json.Unmarshal(respBody, &idpResp); err != nil {
			log.Printf("ERROR: Failed to unmarshal IdP response after primary auth: %v", err)
			resp.AuthResult = -1
			goto sendResponse
		}

		if idpResp.FlowStatus == "COMPLETED" {
			log.Printf("Authentication successful for %s (completed in step 2)", username)
			resp.AuthResult = 1
			// Clean up session cache
			cacheMutex.Lock()
			delete(sessionCache, req.RequestID)
			cacheMutex.Unlock()
			goto sendResponse
		} else if idpResp.FlowStatus == "INCOMPLETE" && idpResp.NextStep != nil {
			// Store the next step information in the session
			cacheMutex.Lock()
			sessionCache[req.RequestID] = sessionData{
				flowID:          flow,
				nextStep:        idpResp.NextStep,
				currentStepType: idpResp.NextStep.StepType,
			}
			cacheMutex.Unlock()

			// Dynamically generate the prompt for the next step
			resp.Instruction, resp.Questions, resp.Echos = generatePromptFromAuthenticators(idpResp.NextStep.Authenticators)
			resp.AuthResult = 0 // Incomplete
		} else {
			log.Printf("ERROR: Unexpected IdP flow status or missing next step: %s", idpResp.FlowStatus)
			resp.AuthResult = -1
			goto sendResponse
		}
	} else if ok { // Subsequent steps (req.Step > 2)
		// Retrieve session data
		flow := data.flowID
		currentNextStep := data.nextStep

		if currentNextStep == nil || len(currentNextStep.Authenticators) == 0 {
			log.Printf("ERROR: Invalid session state for request ID %s: No next step or authenticators.", req.RequestID)
			resp.AuthResult = -1
			goto sendResponse
		}

		var selectedAuthenticator Authenticator
		var authenticatorParams = make(map[string]interface{})
		var err error

		if len(currentNextStep.Authenticators) > 1 {
			// User is selecting an authenticator
			if len(req.Answers) == 0 {
				log.Printf("ERROR: No authenticator selection provided for request ID %s", req.RequestID)
				resp.AuthResult = -1
				goto sendResponse
			}
			selection, parseErr := strconv.Atoi(req.Answers[0])
			if parseErr != nil || selection < 1 || selection > len(currentNextStep.Authenticators) {
				log.Printf("ERROR: Invalid authenticator selection '%s' for request ID %s", req.Answers[0], req.RequestID)
				resp.AuthResult = -1
				goto sendResponse
			}
			selectedAuthenticator = currentNextStep.Authenticators[selection-1] // Adjust for 0-based index
		} else {
			// Only one authenticator available, it's implicitly selected
			selectedAuthenticator = currentNextStep.Authenticators[0]
			// Populate params from answers for this single authenticator
			if len(req.Answers) != len(selectedAuthenticator.RequiredParams) {
				log.Printf("ERROR: Mismatch in number of answers and required params for authenticator %s. Expected %d, got %d.",
					selectedAuthenticator.DisplayName, len(selectedAuthenticator.RequiredParams), len(req.Answers))
				resp.AuthResult = -1
				goto sendResponse
			}
			for i, param := range selectedAuthenticator.RequiredParams {
				authenticatorParams[param.ParamName] = req.Answers[i]
			}
		}

		// If the selected authenticator has required parameters, and it was *just* selected (not already provided)
		// then the next request will need to prompt for those parameters.
		// This logic needs careful handling to avoid prompting for selection AND parameters in the same step.
		// For simplicity, we assume the client sends selection first, then parameters in the next step.

		// Construct the payload for the IdP based on the selected authenticator and user answers
		payload := map[string]interface{}{
			"flowId": flow,
			"selectedAuthenticator": map[string]interface{}{
				"authenticatorId": selectedAuthenticator.AuthenticatorID,
				"params":          authenticatorParams,
			},
		}

		// If this is a selection step, and the selected authenticator has parameters,
		// we need to set up the next prompt for those parameters.
		// Otherwise, we send the current answers as parameters.
		if selectedAuthenticator.PromptType == "SELECT" && len(selectedAuthenticator.RequiredParams) > 0 {
			// This case means the user selected an authenticator, and now we need to prompt for its params.
			// This is a bit tricky with the current `req.Step` model.
			// A better approach would be to have the client always send the selected authenticator ID
			// and then the parameters in the *next* request.
			// For now, we'll assume the answers provided are for the parameters of the *already selected* authenticator.
			// The `generatePromptFromAuthenticators` should handle the case where a single authenticator requires input.
			// If the current step was a selection, and the user provided a selection,
			// the next step should be to prompt for the parameters of the *chosen* authenticator.
			// The `currentNextStep` in session will still reflect the multiple authenticators.
			// We need to update `currentNextStep` to reflect the chosen authenticator's params for the next client prompt.

			// For now, let's assume `req.Answers` directly contain the parameters for the *implicitly* selected authenticator
			// or the parameters after a selection.
			// The `generatePromptFromAuthenticators` will handle the output for the client.
		}

		respBody, err = postJSON(client, idpURL, payload)
		if err != nil {
			log.Printf("ERROR: Authentication step failed for %s: %v", req.Username, err)
			resp.AuthResult = -1
			goto sendResponse
		}

		var idpResp IdPResponse
		if err := json.Unmarshal(respBody, &idpResp); err != nil {
			log.Printf("ERROR: Failed to unmarshal IdP response in subsequent step: %v", err)
			resp.AuthResult = -1
			goto sendResponse
		}

		if idpResp.FlowStatus == "COMPLETED" {
			log.Printf("Authentication successful for %s", req.Username)
			resp.AuthResult = 1
			// Extract authorization code
			if idpResp.AuthorizationCode != "" {
				// Use idpResp.AuthorizationCode
				log.Printf("Authorization Code: %s", idpResp.AuthorizationCode)
			} else if idpResp.AuthData != nil {
				if code, ok := idpResp.AuthData["code"].(string); ok && code != "" {
					// Use code from authData
					log.Printf("Authorization Code (from authData): %s", code)
				}
			}
			// Clean up session cache
			cacheMutex.Lock()
			delete(sessionCache, req.RequestID)
			cacheMutex.Unlock()
		} else if idpResp.FlowStatus == "INCOMPLETE" && idpResp.NextStep != nil {
			// Update session with the new next step
			cacheMutex.Lock()
			sessionCache[req.RequestID] = sessionData{
				flowID:          flow,
				nextStep:        idpResp.NextStep,
				currentStepType: idpResp.NextStep.StepType,
			}
			cacheMutex.Unlock()

			// Dynamically generate the prompt for the client
			resp.Instruction, resp.Questions, resp.Echos = generatePromptFromAuthenticators(idpResp.NextStep.Authenticators)
			resp.AuthResult = 0 // Still incomplete
		} else {
			log.Printf("ERROR: Authentication failed or unexpected IdP response for %s: %s", req.Username, idpResp.FlowStatus)
			if idpResp.Error != "" {
				log.Printf("IdP Error Message: %s", idpResp.Error)
				resp.Instruction = "Authentication failed: " + idpResp.Error
			} else {
				resp.Instruction = "Authentication failed. Please try again."
			}
			resp.AuthResult = -1
		}
	} else {
		// No session data found for subsequent steps or invalid step
		log.Printf("ERROR: Invalid request step %d or no session found for ID %s", req.Step, req.RequestID)
		resp.AuthResult = -1
		resp.Instruction = "Authentication session expired or invalid. Please start over."
	}

sendResponse:
	out, err := json.Marshal(resp)
	if err != nil {
		log.Printf("ERROR: Failed to marshal response to client: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	log.Printf("send: %s", out)
	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

// CustomerInfo represents the 200/201 response structure
type CustomerInfo struct {
	IsValidCustomer bool     `json:"isValidCustomer"`
	ProjectKeys     []string `json:"projectKeys"`
}

// ErrorMessage represents the 400/500 response structure
type ErrorMessage struct {
	Message string `json:"message"`
}

// --- Dummy Data Setup ---

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
