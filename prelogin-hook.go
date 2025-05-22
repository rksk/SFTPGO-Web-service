package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type SFTPGoUser struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
}

type UserVirtualFolder struct {
	Name        string `json:"name"`
	VirtualPath string `json:"virtual_path"`
}

type MinimalSFTPGoUser struct {
	Username       string              `json:"username"`
	HomeDir        string              `json:"home_dir"`
	Permissions    map[string][]string `json:"permissions"`
	Status         int                 `json:"status"`
	VirtualFolders []UserVirtualFolder `json:"virtual_folders,omitempty"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

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
	TokenURL       = os.Getenv("TOKEN_URL")
	SCIMBaseURL    = os.Getenv("SCIM_BASE_URL")
	FetchFolderAPI = os.Getenv("FETCH_FOLDER_API")
	AdminTokenURL  = os.Getenv("ADMIN_TOKEN_URL")
	AdminUser      = os.Getenv("ADMIN_USER")
	AdminKey       = os.Getenv("ADMIN_KEY")
	SftpgoFolders  = os.Getenv("SFTPGO_FOLDERS")
	FolderPath     = os.Getenv("FOLDER_PATH")
	SftpgoFolders2 = os.Getenv("SFTPGO_FOLDERS2")
	SftpgoFolders3 = os.Getenv("SFTPGO_FOLDERS3")
	CheckRole      = os.Getenv("CHECK_ROLE")
	DIRPath        = os.Getenv("DIR_PATH")
	SCIMScope      = os.Getenv("SCIM_SCOPE")
)

func sanitizeUsername(u string) string {
	safe := strings.ReplaceAll(u, "@", "_")
	safe = strings.ReplaceAll(safe, ".", "_")
	safe = strings.ReplaceAll(safe, "/", "_")
	return safe
}

func getBearerToken() (string, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", ClientID)
	data.Set("client_secret", ClientSecret)
	data.Set("scope", SCIMScope)

	req, err := http.NewRequest("POST", TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("error creating token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error sending token request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token request failed: status %d, body: %s", resp.StatusCode, body)
	}

	var tr TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("failed to parse token response: %v", err)
	}
	return tr.AccessToken, nil
}

func getAsgardeoUser(username, token string) (*AsgardeoUser, error) {
	asgUser := username
	if !strings.Contains(username, "/") {
		asgUser = "DEFAULT/" + username
	}
	filter := fmt.Sprintf(`userName eq "%s"`, asgUser)
	params := url.Values{}
	params.Set("filter", filter)
	url := fmt.Sprintf("%s?%s", SCIMBaseURL, params.Encode())

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("SCIM request creation failed: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("SCIM request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("SCIM request failed: status %d, body: %s", resp.StatusCode, body)
	}

	var result struct {
		TotalResults int            `json:"totalResults"`
		Resources    []AsgardeoUser `json:"Resources"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse SCIM response: %v", err)
	}
	if result.TotalResults < 1 {
		return nil, fmt.Errorf("user not found in Asgardeo")
	}
	return &result.Resources[0], nil
}

func getUserFolderList(username string) []string {
	api := fmt.Sprintf(FetchFolderAPI,
		url.QueryEscape(username),
	)
	req, err := http.NewRequest("GET", api, nil)
	if err != nil {
		log.Printf("folder list request error: %v", err)
		return nil
	}
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil
	}
	defer resp.Body.Close()

	var folders []string
	json.NewDecoder(resp.Body).Decode(&folders)
	return folders
}

func getSftpgoAdminToken() (string, error) {
	req, err := http.NewRequest("GET", AdminTokenURL, nil)
	if err != nil {
		return "", fmt.Errorf("error creating SFTPGo token request: %v", err)
	}
	req.SetBasicAuth(AdminUser, AdminKey)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error sending SFTPGo token request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("SFTPGo token request failed: status %d, body: %s", resp.StatusCode, body)
	}
	var tr TokenResponse
	json.NewDecoder(resp.Body).Decode(&tr)
	return tr.AccessToken, nil
}

func checkFolderExists(name, token string) (bool, error) {
	endpoint := fmt.Sprintf(SftpgoFolders, name)
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return false, fmt.Errorf("error creating folder check request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("error sending folder check request: %v", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, body)
	}
}

func createFolder(name, token, user string) error {
	path := filepath.Join(FolderPath, name)
	os.MkdirAll(path, 0755)
	payload := map[string]interface{}{
		"name":         name,
		"mapped_path":  path,
		"virtual_path": "/" + name,
		"description":  "Created via API",
		"users":        []string{user},
	}
	b, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", SftpgoFolders2, strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("folder creation failed: %d %s", resp.StatusCode, body)
	}
	return nil
}

func provisionUserFolders(user string, folders []string) error {
	log.Printf("Provisioning folders for user: %s", user)
	token, err := getSftpgoAdminToken()
	if err != nil {
		return err
	}
	for _, f := range folders {
		exists, err := checkFolderExists(f, token)
		if err != nil {
			log.Printf("checkFolder %s error: %v", f, err)
			continue
		}
		if !exists {
			if err := createFolder(f, token, user); err != nil {
				log.Printf("createFolder %s error: %v", f, err)
			}
		}
	}
	return nil
}

func getAllFolders(token string) ([]UserVirtualFolder, error) {
	endpoint := SftpgoFolders3
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating folders list request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending folders list request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("folders list request failed: status %d, body: %s", resp.StatusCode, body)
	}
	var folders []struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&folders); err != nil {
		return nil, fmt.Errorf("failed to decode folders list: %v", err)
	}
	result := make([]UserVirtualFolder, len(folders))
	for i, f := range folders {
		result[i] = UserVirtualFolder{Name: f.Name, VirtualPath: "/" + f.Name}
	}
	return result, nil
}

func preLoginHook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var u SFTPGoUser
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		log.Printf("Invalid payload: %v", err)
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}
	if u.ID != 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	user := u.Username
	if user == "" {
		http.Error(w, "No username", http.StatusBadRequest)
		return
	}
	token, err := getBearerToken()
	if err != nil {
		http.Error(w, "Auth error", http.StatusInternalServerError)
		return
	}
	asg, err := getAsgardeoUser(user, token)
	if err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}
	role := strings.ToLower(asg.Wso2Schema.UserRole)
	isWSO2 := role == CheckRole

	var home string
	var folders []string
	perms := make(map[string][]string)
	var vfs []UserVirtualFolder

	if isWSO2 {
		home = FolderPath
		// Fetch all existing folders for WSO2 users
		sftpgoToken, err := getSftpgoAdminToken()
		if err != nil {
			log.Printf("Failed to get SFTPGo token: %v", err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		allFolders, err := getAllFolders(sftpgoToken)
		if err != nil {
			log.Printf("Failed to get all folders: %v", err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		vfs = allFolders
		perms["/"] = []string{"*"}
		for _, f := range allFolders {
			perms[f.VirtualPath] = []string{"*"}
		}
	} else {
		home = filepath.Join(DIRPath, sanitizeUsername(user))
		os.MkdirAll(home, 0755)
		folders = getUserFolderList(user)
		if len(folders) == 0 {
			if asg.CustomUser.SftpAdminFolder != "" {
				folders = []string{asg.CustomUser.SftpAdminFolder}
			} else {
				folders = []string{sanitizeUsername(user)}
			}
		}
		if err := provisionUserFolders(user, folders); err != nil {
			log.Printf("Failed to provision folders: %v", err)
		}
		perms["/"] = []string{"list", "download", "upload"}
		for _, f := range folders {
			p := "/" + f
			perms[p] = []string{"upload", "list", "download", "create_dirs", "delete"}
			vfs = append(vfs, UserVirtualFolder{Name: f, VirtualPath: p})
		}
	}

	res := MinimalSFTPGoUser{
		Username:       user,
		HomeDir:        home,
		Permissions:    perms,
		Status:         1,
		VirtualFolders: vfs,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func main() {
	http.HandleFunc("/webhook", preLoginHook)
	log.Println("Listening on :3000/pre-login")
	if err := http.ListenAndServe(":3000", nil); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
