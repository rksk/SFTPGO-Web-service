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
	SftpgoFolders  = os.Getenv("SFTPGO_FOLDERS") // Used for GET /folders/{name}
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
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("WARN: Folder list API for user %s returned status %d, body: %s", username, resp.StatusCode, body)
		return nil
	}
	defer resp.Body.Close()

	var folders []string
	if err := json.NewDecoder(resp.Body).Decode(&folders); err != nil {
		log.Printf("ERROR: Failed to decode custom folder list for user %s: %v", username, err)
		return nil
	}
	log.Printf("Successfully retrieved %d custom folders for user %s.", len(folders), username)
	return folders
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

	if u.ID != 0 {
		log.Printf("INFO: SFTPGo user ID is not 0 (%d). Returning HTTP 204.", u.ID)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	user := u.Username
	if user == "" {
		log.Printf("ERROR: No username provided in pre-login hook payload.")
		http.Error(w, "No username", http.StatusBadRequest)
		return
	}
	log.Printf("Processing pre-login hook for username: %s", user)

	token, err := getBearerToken()
	if err != nil {
		log.Printf("ERROR: Failed to get bearer token for user %s: %v", user, err)
		http.Error(w, "Auth error", http.StatusInternalServerError)
		return
	}
	log.Println("Bearer token obtained successfully.")

	asg, err := getAsgardeoUser(user, token)
	if err != nil {
		log.Printf("ERROR: Failed to get Asgardeo user '%s': %v", user, err)
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}
	log.Printf("Asgardeo user details fetched for %s: %+v", user, asg)

	role := strings.ToLower(asg.Wso2Schema.UserRole)
	isWSO2 := role == CheckRole
	log.Printf("User '%s' role: '%s'. Is WSO2 user ('%s')? %t", user, role, CheckRole, isWSO2)

	var home string
	var folders []string
	perms := make(map[string][]string)
	var vfs []UserVirtualFolder

	if isWSO2 {
		log.Printf("Configuring SFTPGo user '%s' as WSO2 role.", user)
		home = FolderPath
		log.Printf("Setting home directory to: %s", home)

		sftpgoToken, err := getSftpgoAdminToken()
		if err != nil {
			log.Printf("ERROR: Failed to get SFTPGo token for WSO2 user '%s' folder configuration: %v", user, err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		log.Println("SFTPGo admin token obtained for WSO2 user.")

		allFolders, err := getAllFolders(sftpgoToken)
		if err != nil {
			log.Printf("ERROR: Failed to get all SFTPGo folders for WSO2 user '%s': %v", user, err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		vfs = allFolders
		log.Printf("Assigned all %d SFTPGo folders as virtual folders for WSO2 user '%s'.", len(allFolders), user)

		perms["/"] = []string{"*"}
		for _, f := range allFolders {
			perms[f.VirtualPath] = []string{"*"}
		}
		log.Printf("Assigned full permissions to all virtual folders for WSO2 user '%s'.", user)

	} else {
		log.Printf("Configuring SFTPGo user '%s' as non-WSO2 role.", user)
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
			log.Printf("No custom folders found for user '%s' from API.", user)
			if asg.CustomUser.SftpAdminFolder != "" {
				folders = []string{asg.CustomUser.SftpAdminFolder}
				log.Printf("Using 'sftp_admin_folder' from Asgardeo: %v", folders)
			} else {
				folders = []string{sanitizeUsername(user)}
				log.Printf("Using sanitized username as default folder: %v", folders)
			}
		} else {
			log.Printf("Custom folders fetched for user '%s': %v", user, folders)
		}

		if err := provisionUserFolders(user, folders); err != nil {
			log.Printf("ERROR: Failed to provision folders for user '%s': %v", user, err)
			// This is logged, decide if it should result in an HTTP error
		} else {
			log.Printf("Folders provisioned successfully for user '%s'.", user)
		}

		perms["/"] = []string{"list", "download", "upload"} // Default permissions for root
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
	log.Printf("  ADMIN_USER: %s (first 4 chars)", AdminUser[:min(len(AdminUser), 4)]) // Mask sensitive info
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

	log.Println("SFTPGo Pre-Login and Auth Hooks are listening on :9000/prelogin-hook and :9000/auth-hook")
	if err := http.ListenAndServe(":9000", nil); err != nil {
		log.Fatalf("FATAL: Server error: %v", err)
	}
}

// Helper function for min (Go 1.20+ has built-in min)
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type KeyIntRequest struct {
	RequestID string   `json:"request_id"`
	Step      int      `json:"step"`
	Username  string   `json:"username"`
	IP        string   `json:"ip"`
	Answers   []string `json:"answers"`
}

type KeyIntResponse struct {
	Instruction   string   `json:"instruction,omitempty"`
	Questions     []string `json:"questions,omitempty"`
	Echos         []bool   `json:"echos,omitempty"`
	CheckPassword int      `json:"check_password,omitempty"`
	AuthResult    int      `json:"auth_result,omitempty"`
}

type sessionData struct {
	flowID          string
	authenticatorID string
}

var (
	sessionCache = make(map[string]sessionData)
	cacheMutex   = &sync.Mutex{}
)

// func main() {
// 	http.HandleFunc("/auth", keyIntHandler)
// 	log.Println("Starting keyboard-interactive webhook on :3001")
// 	log.Fatal(http.ListenAndServe(":3001", nil))
// }

func keyIntHandler(w http.ResponseWriter, r *http.Request) {
	var req KeyIntRequest
	body, _ := ioutil.ReadAll(r.Body)
	json.Unmarshal(body, &req)
	log.Printf("recv step=%d id=%s user=%s answers=%v", req.Step, req.RequestID, req.Username, req.Answers)

	var resp KeyIntResponse
	client := &http.Client{Timeout: 15 * time.Second}
	idpURL := IdPBasePath + "/oauth2/authn"

	switch req.Step {
	case 1:
		resp.Instruction = "Enter your password:"
		resp.Questions = []string{"Password:"}
		resp.Echos = []bool{false}

	case 2:
		password := ""
		if len(req.Answers) > 0 {
			password = req.Answers[0]
		}

		flow := getFlowID(client)
		cacheMutex.Lock()
		sessionCache[req.RequestID] = sessionData{flowID: flow}
		cacheMutex.Unlock()

		primary := map[string]interface{}{
			"flowId": flow,
			"selectedAuthenticator": map[string]interface{}{
				"authenticatorId": "QmFzaWNBdXRoZW50aWNhdG9yOkxPQ0FM",
				"params":          map[string]interface{}{"username": req.Username, "password": password},
			},
		}

		primResp, err := postJSON(client, idpURL, primary)
		if err != nil {
			log.Printf("Primary auth failed: %v", err)
			resp.AuthResult = -1
			break
		}

		var p map[string]interface{}
		json.Unmarshal(primResp, &p)

		totpAvailable := false
		if ns, ok := p["nextStep"].(map[string]interface{}); ok {
			if auths, ok := ns["authenticators"].([]interface{}); ok {
				for _, a := range auths {
					if obj, _ := a.(map[string]interface{}); obj["authenticatorId"] == "dG90cDpMT0NBTA" {
						totpAvailable = true
					}
				}
			}
		}

		if !totpAvailable {
			// Automatically proceed with email OTP
			otpSelect := map[string]interface{}{
				"flowId": flow,
				"selectedAuthenticator": map[string]interface{}{
					"authenticatorId": "ZW1haWwtb3RwLWF1dGhlbnRpY2F0b3I6TE9DQUw",
				},
			}
			respBody, err := postJSON(client, idpURL, otpSelect)
			if err != nil {
				log.Printf("OTP selection failed: %v", err)
				resp.AuthResult = -1
				break
			}

			var otpResp map[string]interface{}
			if err := json.Unmarshal(respBody, &otpResp); err != nil || otpResp["flowStatus"] != "INCOMPLETE" {
				log.Printf("OTP trigger failed: %s", string(respBody))
				resp.AuthResult = -1
				break
			}

			cacheMutex.Lock()
			sessionCache[req.RequestID] = sessionData{
				flowID:          flow,
				authenticatorID: "ZW1haWwtb3RwLWF1dGhlbnRpY2F0b3I6TE9DQUw",
			}
			cacheMutex.Unlock()

			// Directly prompt for OTP code after sending
			resp.Instruction = "Enter the code:"
			resp.Questions = []string{"Code:"}
			resp.Echos = []bool{false}
		} else {
			// Show method selection for TOTP-enabled users
			resp.Instruction = "Select the authentication method:"
			resp.Questions = []string{"[1] TOTP\n[2] OTP\nEnter:"}
			resp.Echos = []bool{true}
		}

	case 3:
		cacheMutex.Lock()
		data, ok := sessionCache[req.RequestID]
		cacheMutex.Unlock()

		if ok && data.authenticatorID != "" {
			// Handle OTP-only verification immediately
			code := ""
			if len(req.Answers) > 0 {
				code = req.Answers[0]
			}

			verifyPayload := map[string]interface{}{
				"flowId": data.flowID,
				"selectedAuthenticator": map[string]interface{}{
					"authenticatorId": data.authenticatorID,
					"params":          map[string]interface{}{"OTPCode": code},
				},
			}

			respBody, err := postJSON(client, idpURL, verifyPayload)
			if err != nil {
				log.Printf("Verification failed: %v", err)
				resp.AuthResult = -1
				break
			}

			var authResult map[string]interface{}
			if err := json.Unmarshal(respBody, &authResult); err != nil {
				log.Printf("Invalid verification response: %v", err)
				resp.AuthResult = -1
				break
			}

			var authCode string
			if auth, ok := authResult["authorizationCode"].(string); ok && auth != "" {
				authCode = auth
			} else if authData, ok := authResult["authData"].(map[string]interface{}); ok {
				if code, ok := authData["code"].(string); ok && code != "" {
					authCode = code
				}
			}

			if authCode != "" {
				log.Printf("Authentication successful for %s", req.Username)
				resp.AuthResult = 1
			} else {
				log.Printf("Verification failed: %s", string(respBody))
				resp.AuthResult = -1
			}

			cacheMutex.Lock()
			delete(sessionCache, req.RequestID)
			cacheMutex.Unlock()
		} else {
			// Handle TOTP method selection and code prompt
			if len(req.Answers) > 0 {
				if req.Answers[0] == "2" {
					// OTP Flow
					otpSelect := map[string]interface{}{
						"flowId": data.flowID,
						"selectedAuthenticator": map[string]interface{}{
							"authenticatorId": "ZW1haWwtb3RwLWF1dGhlbnRpY2F0b3I6TE9DQUw",
						},
					}
					_, err := postJSON(client, idpURL, otpSelect)
					if err != nil {
						log.Printf("OTP selection failed: %v", err)
						resp.AuthResult = -1
						break
					}

					data.authenticatorID = "ZW1haWwtb3RwLWF1dGhlbnRpY2F0b3I6TE9DQUw"
				} else {
					// TOTP Flow
					totpSelect := map[string]interface{}{
						"flowId": data.flowID,
						"selectedAuthenticator": map[string]interface{}{
							"authenticatorId": "dG90cDpMT0NBTA",
						},
					}
					_, err := postJSON(client, idpURL, totpSelect)
					if err != nil {
						log.Printf("TOTP selection failed: %v", err)
						resp.AuthResult = -1
						break
					}
					data.authenticatorID = "dG90cDpMT0NBTA"
				}

				cacheMutex.Lock()
				sessionCache[req.RequestID] = data
				cacheMutex.Unlock()
			}

			resp.Instruction = "Enter the code:"
			resp.Questions = []string{"Code:"}
			resp.Echos = []bool{false}
		}

	case 4:
		// Only TOTP-enabled users reach here
		code := ""
		if len(req.Answers) > 0 {
			code = req.Answers[0]
		}

		cacheMutex.Lock()
		data, ok := sessionCache[req.RequestID]
		cacheMutex.Unlock()

		if !ok {
			resp.AuthResult = -1
			break
		}

		verifyPayload := map[string]interface{}{
			"flowId": data.flowID,
			"selectedAuthenticator": map[string]interface{}{
				"authenticatorId": data.authenticatorID,
				"params":          map[string]interface{}{"token": code},
			},
		}

		respBody, err := postJSON(client, idpURL, verifyPayload)
		if err != nil {
			log.Printf("Verification failed: %v", err)
			resp.AuthResult = -1
			break
		}

		var authResult map[string]interface{}
		if err := json.Unmarshal(respBody, &authResult); err != nil {
			log.Printf("Invalid verification response: %v", err)
			resp.AuthResult = -1
			break
		}

		var authCode string
		if auth, ok := authResult["authorizationCode"].(string); ok && auth != "" {
			authCode = auth
		} else if authData, ok := authResult["authData"].(map[string]interface{}); ok {
			if code, ok := authData["code"].(string); ok && code != "" {
				authCode = code
			}
		}

		if authCode != "" {
			log.Printf("Authentication successful for %s", req.Username)
			resp.AuthResult = 1
		} else {
			log.Printf("Verification failed: %s", string(respBody))
			resp.AuthResult = -1
		}

		cacheMutex.Lock()
		delete(sessionCache, req.RequestID)
		cacheMutex.Unlock()
	default:
		resp.AuthResult = -1
	}

	out, _ := json.Marshal(resp)
	log.Printf("send: %s", out)
	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

func getFlowID(client *http.Client) string {
	url := IdPBasePath + "/oauth2/authorize/"
	form := "client_id=" + ClientID + "&client_secret=" + ClientSecret + "&response_type=code&redirect_uri=http://sftpdemo.com:8080/web/oidc/redirect&scope=openid&response_mode=direct"
	req, _ := http.NewRequest("POST", url, bytes.NewBufferString(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, _ := client.Do(req)
	b, _ := ioutil.ReadAll(res.Body)
	var fm struct{ FlowId string }
	json.Unmarshal(b, &fm)
	return fm.FlowId
}

func postJSON(client *http.Client, url string, payload interface{}) ([]byte, error) {
	b, _ := json.Marshal(payload)
	res, err := client.Post(url, "application/json", bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP error %d", res.StatusCode)
	}

	body, err := ioutil.ReadAll(res.Body)
	return body, err
}
