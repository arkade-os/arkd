package filestore

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	walletstore "github.com/arkade-os/arkd/pkg/client-lib/wallet/singlekey/store"
	"github.com/btcsuite/btcd/btcec/v2"
)

const (
	filename = "state.json"
)

type walletData struct {
	EncryptedPrvkey string `json:"encrypted_private_key"`
	PasswordHash    string `json:"password_hash"`
	PubKey          string `json:"pubkey"`
}

type boardingDescriptor struct {
	Address    string   `json:"address"`
	Tapscripts []string `json:"tapscripts"`
}

func (d walletData) isEmpty() bool {
	return d == walletData{}
}

func (d walletData) decode() walletstore.WalletData {
	encryptedPrvkey, _ := hex.DecodeString(d.EncryptedPrvkey)
	passwordHash, _ := hex.DecodeString(d.PasswordHash)
	buf, _ := hex.DecodeString(d.PubKey)
	pubkey, _ := btcec.ParsePubKey(buf)
	return walletstore.WalletData{
		EncryptedPrvkey: encryptedPrvkey,
		PasswordHash:    passwordHash,
		PubKey:          pubkey,
	}
}

func (d walletData) asMap() map[string]any {
	return map[string]any{
		"encrypted_private_key": d.EncryptedPrvkey,
		"password_hash":         d.PasswordHash,
		"pubkey":                d.PubKey,
	}
}

type fileStore struct {
	filePath string
}

func NewWalletStore(baseDir string) (walletstore.WalletStore, error) {
	datadir := cleanAndExpandPath(baseDir)
	if err := makeDirectoryIfNotExists(datadir); err != nil {
		return nil, fmt.Errorf("failed to initialize datadir: %s", err)
	}
	filePath := filepath.Join(datadir, filename)

	fileStore := &fileStore{filePath}

	if _, err := fileStore.open(); err != nil {
		return nil, fmt.Errorf("failed to open file store: %s", err)
	}

	return fileStore, nil
}

func (s *fileStore) AddWallet(data walletstore.WalletData) error {
	wd := &walletData{
		EncryptedPrvkey: hex.EncodeToString(data.EncryptedPrvkey),
		PasswordHash:    hex.EncodeToString(data.PasswordHash),
		PubKey:          hex.EncodeToString(data.PubKey.SerializeCompressed()),
	}

	if err := s.write(wd); err != nil {
		return fmt.Errorf("failed to write to file store: %s", err)
	}
	return nil
}

func (s *fileStore) GetWallet() (*walletstore.WalletData, error) {
	wd, err := s.open()
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		if err := s.write(&walletData{}); err != nil {
			return nil, fmt.Errorf("failed to initialize store: %s", err)
		}
		return nil, nil
	}
	if wd.isEmpty() {
		return nil, nil
	}

	data := wd.decode()
	return &data, nil
}

func (s *fileStore) AddBoardingDescriptor(descriptor walletstore.BoardingDescriptor) error {
	file, err := os.ReadFile(s.filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	}

	currentData := map[string]any{}
	if len(file) > 0 {
		if err := json.Unmarshal(file, &currentData); err != nil {
			return fmt.Errorf("failed to read file store: %s", err)
		}
	}

	descriptors := make([]boardingDescriptor, 0)
	if raw, ok := currentData["boarding_descriptors"]; ok {
		buf, err := json.Marshal(raw)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(buf, &descriptors); err != nil {
			return err
		}
	}

	for _, d := range descriptors {
		if d.Address == descriptor.Address {
			return nil
		}
	}

	descriptors = append(descriptors, boardingDescriptor{
		Address:    descriptor.Address,
		Tapscripts: descriptor.Tapscripts,
	})

	currentData["boarding_descriptors"] = descriptors

	jsonString, err := json.Marshal(currentData)
	if err != nil {
		return err
	}
	return os.WriteFile(s.filePath, jsonString, 0755)
}

func (s *fileStore) GetBoardingDescriptors() ([]walletstore.BoardingDescriptor, error) {
	file, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	currentData := map[string]any{}
	if len(file) > 0 {
		if err := json.Unmarshal(file, &currentData); err != nil {
			return nil, fmt.Errorf("failed to read file store: %s", err)
		}
	}

	raw, ok := currentData["boarding_descriptors"]
	if !ok {
		return nil, nil
	}

	buf, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}

	var descriptors []boardingDescriptor
	if err := json.Unmarshal(buf, &descriptors); err != nil {
		return nil, err
	}

	result := make([]walletstore.BoardingDescriptor, 0, len(descriptors))
	for _, d := range descriptors {
		result = append(result, walletstore.BoardingDescriptor{
			Address:    d.Address,
			Tapscripts: d.Tapscripts,
		})
	}
	return result, nil
}

func (s *fileStore) open() (*walletData, error) {
	file, err := os.ReadFile(s.filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to open file store: %s", err)
		}
		if err := s.write(&walletData{}); err != nil {
			return nil, fmt.Errorf("failed to initialize file store: %s", err)
		}
		return &walletData{}, nil
	}

	data := &walletData{}
	if err := json.Unmarshal(file, data); err != nil {
		return nil, fmt.Errorf("failed to read file store: %s", err)
	}
	return data, nil
}

func (s *fileStore) write(data *walletData) error {
	file, err := os.ReadFile(s.filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	}
	currentData := map[string]any{}
	if len(file) > 0 {
		if err := json.Unmarshal(file, &currentData); err != nil {
			return fmt.Errorf("failed to read file store: %s", err)
		}
	}

	mergedData := merge(currentData, data.asMap())

	jsonString, err := json.Marshal(mergedData)
	if err != nil {
		return err
	}

	err = os.WriteFile(s.filePath, jsonString, 0755)
	if err != nil {
		return err
	}

	return nil
}

func cleanAndExpandPath(path string) string {
	if path == "" {
		return ""
	}

	// Expand initial ~ to OS specific home directory.
	if strings.HasPrefix(path, "~") {
		var homeDir string
		u, err := user.Current()
		if err == nil {
			homeDir = u.HomeDir
		} else {
			homeDir = os.Getenv("HOME")
		}

		path = strings.Replace(path, "~", homeDir, 1)
	}

	// NOTE: The os.ExpandEnv doesn't work with Windows-style %VARIABLE%,
	// but the variables can still be expanded via POSIX-style $VARIABLE.
	return filepath.Clean(os.ExpandEnv(path))
}

func makeDirectoryIfNotExists(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, os.ModeDir|0755)
	}
	return nil
}

func merge(maps ...map[string]any) map[string]any {
	merge := make(map[string]any, 0)
	for _, m := range maps {
		for k, v := range m {
			merge[k] = v
		}
	}
	return merge
}
