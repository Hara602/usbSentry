// Package sysutil provides system-level utility functions,
// including cryptographic hash calculations for files and data.
package sysutil

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"io"
	"os"
)

// hashFile computes the hash of a file using the provided hash.Hash algorithm.
// Returns the hex-encoded hash string or an error.
func hashFile(path string, algo func() hash.Hash) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	// Check if path is a directory (optional but user-friendly)
	info, err := f.Stat()
	if err == nil && info.IsDir() {
		return "", &os.PathError{Op: "hash", Path: path, Err: os.ErrInvalid}
	}

	return hashReader(f, algo)
}

// hashReader reads all data from r and returns its hex-encoded hash.
func hashReader(r io.Reader, algo func() hash.Hash) (string, error) {
	h := algo()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// hashBytes computes the hash of a byte slice.
func hashBytes(data []byte, algo func() hash.Hash) string {
	h := algo()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// hashString computes the hash of a string.
func hashString(s string, algo func() hash.Hash) string {
	return hashBytes([]byte(s), algo)
}

// --- File hash functions -------------------------------------------------

// MD5File computes the MD5 hash of a file.
func MD5File(path string) (string, error) {
	return hashFile(path, md5.New)
}

// SHA1File computes the SHA-1 hash of a file.
func SHA1File(path string) (string, error) {
	return hashFile(path, sha1.New)
}

// SHA256File computes the SHA-256 hash of a file.
func SHA256File(path string) (string, error) {
	return hashFile(path, sha256.New)
}

// SHA512File computes the SHA-512 hash of a file.
func SHA512File(path string) (string, error) {
	return hashFile(path, sha512.New)
}

// --- String / byte slice hash functions ----------------------------------

// MD5String returns the MD5 hash of a string.
func MD5String(s string) string {
	return hashString(s, md5.New)
}

// SHA1String returns the SHA-1 hash of a string.
func SHA1String(s string) string {
	return hashString(s, sha1.New)
}

// SHA256String returns the SHA-256 hash of a string.
func SHA256String(s string) string {
	return hashString(s, sha256.New)
}

// SHA512String returns the SHA-512 hash of a string.
func SHA512String(s string) string {
	return hashString(s, sha512.New)
}

// MD5Bytes returns the MD5 hash of a byte slice.
func MD5Bytes(data []byte) string {
	return hashBytes(data, md5.New)
}

// SHA1Bytes returns the SHA-1 hash of a byte slice.
func SHA1Bytes(data []byte) string {
	return hashBytes(data, sha1.New)
}

// SHA256Bytes returns the SHA-256 hash of a byte slice.
func SHA256Bytes(data []byte) string {
	return hashBytes(data, sha256.New)
}

// SHA512Bytes returns the SHA-512 hash of a byte slice.
func SHA512Bytes(data []byte) string {
	return hashBytes(data, sha512.New)
}

// --- Reader hash functions -----------------------------------------------

// MD5Reader computes the MD5 hash of data read from an io.Reader.
func MD5Reader(r io.Reader) (string, error) {
	return hashReader(r, md5.New)
}

// SHA1Reader computes the SHA-1 hash of data read from an io.Reader.
func SHA1Reader(r io.Reader) (string, error) {
	return hashReader(r, sha1.New)
}

// SHA256Reader computes the SHA-256 hash of data read from an io.Reader.
func SHA256Reader(r io.Reader) (string, error) {
	return hashReader(r, sha256.New)
}

// SHA512Reader computes the SHA-512 hash of data read from an io.Reader.
func SHA512Reader(r io.Reader) (string, error) {
	return hashReader(r, sha512.New)
}
