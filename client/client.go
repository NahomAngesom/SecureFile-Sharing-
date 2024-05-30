package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username            string
	Salt                int
	Devices             []string
	EncryptionKey       userlib.PrivateKeyType
	DigitalSignatureKey userlib.DSSignKey
	FilenametoUUID      uuid.UUID
	FilenametoKey       map[string]FileEncrypt
	FileEncryptKey      []byte
	FileVerifyKey       []byte
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type File struct {
	FileOwner          string
	OriginalName       string
	ContentsPtrs       []uuid.UUID
	FileSharedUser     map[string][]string
	ContentEncryptKeys [][]byte
	ContentVerifyKeys  [][]byte
	NumberofAppend     int
}

type HmacAndEnc struct {
	Encrypted []byte
	Hmaced    []byte
}

type Invitation struct {
	InviteFile  uuid.UUID
	FileEncrypt []byte
	FileVerify  []byte
	Sender      string
	FileName    string
}

type FileEncrypt struct {
	EncryptionKey   []byte
	VerificationKey []byte
}

type Envelope struct {
	DecryptKey    []byte
	EncryptInvite []byte
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	//Generate userStruct
	var userdata User
	userdata.Username = username

	//Check if username is empty
	if username == "" {
		return nil, errors.New("Username is empty")
	}

	//Generate deterministic uuid for each username
	hashed := userlib.Hash([]byte(username))[:16]
	userUUID, generated := uuid.FromBytes(hashed)
	if generated != nil {
		return nil, errors.New("Cannot get uuid of username")
	}

	//return error if this username is already used
	_, ok := userlib.DatastoreGet(userUUID)
	if ok {
		return nil, errors.New("username has already been created")
	}

	// userdata.FilenametoUUID = make(map[string]uuid.UUID)
	// userdata.FilenametoKey = make(map[string]FileEncrypt)

	// userdata.FileEncryptKey, _ = uuid.FromBytes(userlib.Hash([]byte(username + "Enc"))[:16])
	// userdata.FileVerifyKey, _ = uuid.FromBytes(userlib.Hash([]byte(username + "Ver"))[:16])

	//generate key pair for symmetric encryption and decryption
	var publicKey, privateKey, ok1 = userlib.PKEKeyGen()
	if ok1 != nil {
		return nil, errors.New("Cannot generate encryption keys")
	}
	//store private key in user struct
	//store public key in keystore
	userdata.EncryptionKey = privateKey
	userlib.KeystoreSet(userdata.Username+"publicEnc", publicKey)

	//generate key pair for digital signature
	var digipri, digipub, ok2 = userlib.DSKeyGen()
	if ok2 != nil {
		return nil, errors.New("Cannot generate digital signature keys")
	}
	//store private key in user struct
	//store public key in keystore
	userdata.DigitalSignatureKey = digipri
	userlib.KeystoreSet(userdata.Username+"publicDig", digipub)

	maps := make(map[string]uuid.UUID)
	marshalledMap, _ := json.Marshal(maps)
	mapID, _ := uuid.FromBytes(userlib.Hash([]byte(username + "filenametouuid"))[:16])
	userlib.DatastoreSet(mapID, marshalledMap)
	userdata.FilenametoUUID = mapID
	fmt.Print(mapID)

	//generate keys for file encryption and verification
	fileKey := userlib.RandomBytes(16)
	fileEncrypt, ok6 := userlib.HashKDF(fileKey, []byte("file Encryption"))
	if ok6 != nil {
		return nil, errors.New("Cannot generate encryption key for the file")
	}
	fileVerify, ok7 := userlib.HashKDF(fileKey, []byte("file verification"))
	if ok7 != nil {
		return nil, errors.New("Cannot generate verification key for the file")
	}

	userdata.FileEncryptKey = fileEncrypt[:16]
	userdata.FileVerifyKey = fileVerify[:16]
	// fmt.Print(userdata.FileEncryptKey)
	// fmt.Print(userdata.FileVerifyKey)

	//generate random salt to encrypt the user struct
	saltEnc := userlib.RandomBytes(16)
	//generate HMAC key from password and modified version of username, so that HMAC and encryption doesn't use the same key
	hmacKey := userlib.Argon2Key([]byte(password), []byte(username+"anotherVersionForHmac"), 16)
	hashedUserStruct, ok3 := json.Marshal(userdata)
	if ok3 != nil {
		return nil, errors.New("Cannot Marshal the user struct")
	}
	//encrypt the user struct using the secret key generated by password, username, and random salt.
	encryptedUserStruct := userlib.SymEnc(userlib.Argon2Key([]byte(password), []byte(username), 16), saltEnc, hashedUserStruct)
	//HMAC the user struct
	hmacedUserStruct, ok4 := userlib.HMACEval(hmacKey, encryptedUserStruct)
	if ok4 != nil {
		return nil, errors.New("Cannot HMAC the user struct")
	}

	//store the (enc(userstruct), hmac(enc(userstruct))) in datastore for confidentiality and integrity purpose
	var dataToStore HmacAndEnc
	dataToStore.Encrypted = encryptedUserStruct
	dataToStore.Hmaced = hmacedUserStruct

	marshalledData, ok5 := json.Marshal(dataToStore)
	if ok5 != nil {
		return nil, errors.New("Cannot marshalled the (enc(file), hmac(enc(file)))")
	}

	//store the encrypted-then-mac user struct in the datastore.
	userlib.DatastoreSet(userUUID, marshalledData)

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	//find the uuid from username
	useruuid, ok := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if ok != nil {
		return nil, errors.New("Cannot find matching uuid with this username")
	}
	//find the encrypt-then-hmac struct using uuid
	hmacedInfo, ok1 := userlib.DatastoreGet(useruuid)
	if ok1 != true {
		return nil, errors.New("Cannot find hmaced user struct with this username")
	}
	var hmacedpair HmacAndEnc
	//compare the existing hmac in the struct with recalculated hmac
	ok2 := json.Unmarshal(hmacedInfo, &hmacedpair)
	if ok2 != nil {
		return nil, errors.New("Cannot Unmarshall the encrypt-then-hmac struct")
	}
	//recalculate the hmac
	hmacKey := userlib.Argon2Key([]byte(password), []byte(username+"anotherVersionForHmac"), 16)
	recalculatedHmac, ok3 := userlib.HMACEval(hmacKey, hmacedpair.Encrypted)
	if ok3 != nil {
		return nil, errors.New("Cannot recalculate the hmac using encrypted user struct")
	}
	//if two hmacs do not match, return error
	if userlib.HMACEqual(recalculatedHmac, hmacedpair.Hmaced) != true {
		return nil, errors.New("The user struct has been tampered with")
	}

	//if the user struct is not tampered with, we can now unmarshall and decrypt it
	marshalledUserStruct := userlib.SymDec(userlib.Argon2Key([]byte(password), []byte(username), 16), hmacedpair.Encrypted)
	ok4 := json.Unmarshal(marshalledUserStruct, userdataptr)
	if ok4 != nil {
		return nil, errors.New("Cannot unmarshall the decrypted user struct")
	}

	// maps := make(map[string]uuid.UUID)
	// marshalledMap, _ := json.Marshal(maps)
	// mapID, _ := uuid.FromBytes(userlib.Hash([]byte(username + "filenametouuid"))[:16])
	// userlib.DatastoreSet(mapID, marshalledMap)
	userdataptr.FilenametoUUID, _ = uuid.FromBytes(userlib.Hash([]byte(username + "filenametouuid"))[:16])
	fmt.Print("lets see")
	// fmt.Print(userdataptr.FileEncryptKey)
	// fmt.Print(userdataptr.FileVerifyKey)
	fmt.Print(userdataptr.FilenametoUUID)

	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	var userfilemap map[string]uuid.UUID
	marshalledMaps, exists := userlib.DatastoreGet(userdata.FilenametoUUID)
	if exists != true {
		return errors.New("cannot find filemap")
	}
	json.Unmarshal(marshalledMaps, &userfilemap)
	//hash the filename to a deterministic uuid
	storageKey, ok1 := uuid.FromBytes(append(userlib.Hash([]byte(filename))[:8], userlib.Hash([]byte(userdata.Username))[:8]...))
	if ok1 != nil {
		return errors.New("Cannot generate UUID for this filename")
	}

	//check if the file is already in the datastore, if so, delete the file from user struct and overwrite it

	//generate file struct

	var tempFile File
	var fileTostore File
	var fileHMAC HmacAndEnc
	marshalledFile, ok := userlib.DatastoreGet(storageKey)
	// fmt.Print(ok)
	if ok == true {
		json.Unmarshal(marshalledFile, &tempFile)
		// fmt.Print(tempFile.FileOwner)
		// fmt.Print(tempFile.OriginalName)
		fileID, _ := userfilemap[filename]
		marshalledRealFileHmac, found := userlib.DatastoreGet(fileID)
		if found != true {
			return errors.New("cannot find the file struct")
		}

		json.Unmarshal(marshalledRealFileHmac, &fileHMAC)

		encryptedFile := fileHMAC.Encrypted
		hmacedFile := fileHMAC.Hmaced

		fileverifyKey := userdata.FileVerifyKey
		filedecryptKey := userdata.FileEncryptKey
		reHmac, ok1 := userlib.HMACEval(fileverifyKey, encryptedFile)
		if ok1 != nil {
			return errors.New("Cannot recalculate the HMAC for file struct")
		}
		//if hmacs do not match, the file struct has been tampered with
		check := userlib.HMACEqual(reHmac, hmacedFile)
		if check != true {
			return errors.New("The file struct has been tampered with")
		}
		//if the file struct is fine, decrypt it
		marshalledfile := userlib.SymDec(filedecryptKey, encryptedFile)
		json.Unmarshal(marshalledfile, &fileTostore)

		fmt.Print(fileTostore.FileOwner)
		fmt.Print(fileTostore.FileSharedUser)
		print("-------------")

		mapID, _ := uuid.FromBytes(append(userlib.Hash([]byte(fileTostore.FileOwner))[:8], userlib.Hash([]byte("sharemaps"))[:8]...))
		marshalledShareMap, _ := userlib.DatastoreGet(mapID)
		var sharemap map[string][]string
		json.Unmarshal(marshalledShareMap, &sharemap)
		fileTostore.FileSharedUser = sharemap
		fmt.Print(fileTostore.FileSharedUser)
		fmt.Print(fileTostore.FileOwner)

	}

	fmt.Print(len(fileTostore.FileSharedUser))

	if len(fileTostore.FileSharedUser) == 0 {
		shareMap := make(map[string][]string)
		shareMapID, _ := uuid.FromBytes(append(userlib.Hash([]byte(userdata.Username))[:8], userlib.Hash([]byte("sharemaps"))[:8]...))
		shareMap["origin"] = append(shareMap["origin"], userdata.Username)
		marshalledMap, _ := json.Marshal(shareMap)
		userlib.DatastoreSet(shareMapID, marshalledMap)
	}

	if len(fileTostore.FileSharedUser) <= 1 {
		mapID, _ := uuid.FromBytes(append(userlib.Hash([]byte(userdata.Username))[:8], userlib.Hash([]byte("sharemaps"))[:8]...))
		marshalledShareMap, _ := userlib.DatastoreGet(mapID)
		var sharemap map[string][]string
		json.Unmarshal(marshalledShareMap, &sharemap)

		fileTostore.FileSharedUser = sharemap

	}

	fmt.Print(fileTostore.FileSharedUser)

	valid := false
	for sender, receiver := range fileTostore.FileSharedUser {
		if sender == userdata.Username {
			valid = true
		}
		for i := 0; i < len(receiver); i++ {
			if receiver[i] == userdata.Username {
				valid = true
			}
		}
	}

	if valid == false {
		return errors.New("not allowed to access")
	}
	// fmt.Print(fileTostore.FileOwner)
	// fmt.Print(fileTostore.OriginalName)

	//marshall the contents of the file
	//encrypt the hashed contents
	hashedcontent, ok11 := json.Marshal(content)
	if ok11 != nil {
		return errors.New("Cannot hash the content")
	}
	//generate key root for HashKDF
	rootKey := userlib.RandomBytes(16)
	//generate encrypt key for content
	contentEncrypt, ok11 := userlib.HashKDF(rootKey, []byte("content Encryption"))
	if ok11 != nil {
		return errors.New("Cannot generate encryption key for the content")
	}
	//generate hmac key for content
	contentVerify, ok2 := userlib.HashKDF(rootKey, []byte("content verification"))
	if ok2 != nil {
		return errors.New("Cannot generate verification key for the content")
	}
	//encrypt-then-hmac the content
	salt := userlib.RandomBytes(16)
	encryptedContent := userlib.SymEnc(contentEncrypt[:16], salt, hashedcontent)
	hmacedContent, ok3 := userlib.HMACEval(contentVerify[:16], encryptedContent)
	if ok3 != nil {
		return errors.New("Cannnot HMAC the content")
	}
	//store the hmac sturct of the content in datastore, put the pointer to content in file sturct
	var hmaccontent HmacAndEnc
	hmaccontent.Encrypted = encryptedContent
	hmaccontent.Hmaced = hmacedContent
	//marshall the hmaced content
	hashedAndEncryptedStruct, ok5 := json.Marshal(hmaccontent)
	if ok5 != nil {
		return errors.New("Cannot Marshall the hmac sturct")
	}
	//generate a random uuid for the content
	contentUUID, ok4 := uuid.FromBytes(userlib.RandomBytes(16))
	if ok4 != nil {
		return errors.New("Cannot generate uuid for the encrypted content")
	}
	//put the hmaced content in datastore
	userlib.DatastoreSet(contentUUID, hashedAndEncryptedStruct)
	//add pointers in file struct
	fileTostore.NumberofAppend = 0
	fmt.Print(contentUUID)

	fileTostore.ContentsPtrs = nil
	fileTostore.ContentsPtrs = append(fileTostore.ContentsPtrs, contentUUID)
	//fileTostore.ContentsPtrs[0] = contentUUID
	if fileTostore.FileOwner == "" {
		fileTostore.FileOwner = userdata.Username
		fileTostore.OriginalName = filename
	}
	fmt.Print(fileTostore.ContentsPtrs)

	fileTostore.ContentEncryptKeys = nil
	fileTostore.ContentVerifyKeys = nil
	fileTostore.ContentEncryptKeys = append(fileTostore.ContentEncryptKeys, contentEncrypt[:16])
	fileTostore.ContentVerifyKeys = append(fileTostore.ContentVerifyKeys, contentVerify[:16])
	//fileTostore.ContentEncryptKeys[0] = contentEncrypt[:16]
	//fileTostore.ContentVerifyKeys[0] = contentVerify[:16]

	hashedFile, ok8 := json.Marshal(fileTostore)
	if ok8 != nil {
		return errors.New("Cannot Marshall the file struct")
	}

	salt2 := userlib.RandomBytes(16)
	encryptedFile := userlib.SymEnc(userdata.FileEncryptKey, salt2, hashedFile)
	hmacedFile, ok9 := userlib.HMACEval(userdata.FileVerifyKey, encryptedFile)
	if ok9 != nil {
		return errors.New("Cannot hmac the file struct")
	}

	var hmacFile HmacAndEnc
	hmacFile.Encrypted = encryptedFile
	hmacFile.Hmaced = hmacedFile

	marshalledData, ok5 := json.Marshal(hmacFile)
	if ok5 != nil {
		return errors.New("Cannot marshalled hmacFile")
	}

	fmt.Print(fileTostore.OriginalName)
	fmt.Print(fileTostore.FileOwner)
	randomUUID, ok10 := uuid.FromBytes(append(userlib.Hash([]byte(fileTostore.OriginalName))[:8], userlib.Hash([]byte(fileTostore.FileOwner))[:8]...))
	if ok10 != nil {
		return errors.New("Cannot generate UUID for the file struct")
	}
	//store the encrypted-then-mac user struct in the datastore.
	userlib.DatastoreSet(randomUUID, marshalledData)

	// marshalledFileKey, _ := json.Marshal(fileEncrypt[:16])
	// marshalledVerKey, _ := json.Marshal(fileVerify[:16])
	// userlib.DatastoreSet(userdata.FileEncryptKey, marshalledFileKey)
	// userlib.DatastoreSet(userdata.FileVerifyKey, marshalledVerKey)

	var filemap map[string]uuid.UUID
	marshalledMap, exists := userlib.DatastoreGet(userdata.FilenametoUUID)
	if exists != true {
		return errors.New("cannot find filemap")
	}
	json.Unmarshal(marshalledMap, &filemap)

	filemap[filename] = randomUUID

	marshalledUpdateMap, _ := json.Marshal(filemap)
	userlib.DatastoreSet(userdata.FilenametoUUID, marshalledUpdateMap)

	// fmt.Print(maps)
	// fmt.Print(userdata.FilenametoUUID)

	return nil

}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	//hash the filename to a deterministic uuid
	var filehmacstruct HmacAndEnc
	var file File
	var filemap map[string]uuid.UUID
	marshalledMap, exists := userlib.DatastoreGet(userdata.FilenametoUUID)
	if exists != true {
		return errors.New("cannot find filemap")
	}
	json.Unmarshal(marshalledMap, &filemap)

	fileID := filemap[filename]
	// fmt.Print(fileID)
	marshalledfilehmacstruct, exist := userlib.DatastoreGet(fileID)
	if exist != true {
		return errors.New("Cannot find the file struct corresponding to this filename")
	}
	ok := json.Unmarshal(marshalledfilehmacstruct, &filehmacstruct)
	if ok != nil {
		return errors.New("Cannot unmarshall the file hmac struct")
	}
	encryptedFile := filehmacstruct.Encrypted
	hmacedFile := filehmacstruct.Hmaced

	//recalculate hmac for file struct
	// var fileverifyKey []byte
	// marshalledKeyFile, _ := userlib.DatastoreGet(userdata.FileVerifyKey)
	// json.Unmarshal(marshalledKeyFile, &fileverifyKey)

	// var filedecryptKey []byte
	// marshalledEncFile, _ := userlib.DatastoreGet(userdata.FileEncryptKey)
	// json.Unmarshal(marshalledEncFile, &filedecryptKey)

	fileverifyKey := userdata.FileVerifyKey
	filedecryptKey := userdata.FileEncryptKey

	reHmac, ok1 := userlib.HMACEval(fileverifyKey, encryptedFile)
	if ok1 != nil {
		return errors.New("Cannot recalculate the HMAC for file struct")
	}
	// fmt.Print("lallalalalalalal")
	// fmt.Print(reHmac)
	// fmt.Print(hmacedFile)
	//if hmacs do not match, the file struct has been tampered with
	check := userlib.HMACEqual(reHmac, hmacedFile)
	if check != true {
		return errors.New("The file struct has been tampered with")
	}
	//if the file struct is fine, decrypt it
	marshalledfile := userlib.SymDec(filedecryptKey, encryptedFile)
	check2 := json.Unmarshal(marshalledfile, &file)
	if check2 != nil {
		return errors.New("Cannot unmarshall the file struct")
	}
	//hash the contents of the file
	//encrypt the hashed contents
	// fmt.Print(file.FileOwner)
	mapID, _ := uuid.FromBytes(append(userlib.Hash([]byte(file.FileOwner))[:8], userlib.Hash([]byte("sharemaps"))[:8]...))
	marshalledShareMap, _ := userlib.DatastoreGet(mapID)
	var sharemap map[string][]string
	json.Unmarshal(marshalledShareMap, &sharemap)

	file.FileSharedUser = sharemap
	fmt.Print(file.FileSharedUser)

	valid := false
	for sender, receiver := range file.FileSharedUser {
		if sender == userdata.Username {
			valid = true
		}
		for i := 0; i < len(receiver); i++ {
			if receiver[i] == userdata.Username {
				valid = true
			}
		}
	}

	if valid == false {
		return errors.New("not allowed to access")
	}

	hashedcontent, ok11 := json.Marshal(content)
	if ok11 != nil {
		return errors.New("Cannot hash the content")
	}
	//generate key root for HashKDF
	rootKey := userlib.RandomBytes(16)
	//generate encrypt key for content
	contentEncrypt, ok := userlib.HashKDF(rootKey, []byte("content Encryption"))
	if ok != nil {
		return errors.New("Cannot generate encryption key for the content")
	}
	//generate hmac key for content
	contentVerify, ok2 := userlib.HashKDF(rootKey, []byte("content verification"))
	if ok2 != nil {
		return errors.New("Cannot generate verification key for the content")
	}
	//encrypt-then-hmac the content
	salt := userlib.RandomBytes(16)
	encryptedContent := userlib.SymEnc(contentEncrypt[:16], salt, hashedcontent)
	hmacedContent, ok3 := userlib.HMACEval(contentVerify[:16], encryptedContent)
	if ok3 != nil {
		return errors.New("Cannnot HMAC the content")
	}
	//store the hmac sturct of the content in datastore, put the pointer to content in file sturct
	var hmaccontent HmacAndEnc
	hmaccontent.Encrypted = encryptedContent
	hmaccontent.Hmaced = hmacedContent
	//marshall the hmaced content
	hashedAndEncryptedStruct, ok5 := json.Marshal(hmaccontent)
	if ok5 != nil {
		return errors.New("Cannot Marshall the hmac sturct")
	}

	contentUUID, ok4 := uuid.FromBytes(userlib.RandomBytes(16))
	if ok4 != nil {
		return errors.New("Cannot generate uuid for the encrypted content")
	}
	//put the hmaced content in datastore
	userlib.DatastoreSet(contentUUID, hashedAndEncryptedStruct)

	file.NumberofAppend = file.NumberofAppend + 1
	file.ContentsPtrs = append(file.ContentsPtrs, contentUUID)
	file.ContentEncryptKeys = append(file.ContentEncryptKeys, contentEncrypt[:16])
	file.ContentVerifyKeys = append(file.ContentVerifyKeys, contentVerify[:16])

	hashedFile, ok8 := json.Marshal(file)
	if ok8 != nil {
		return errors.New("Cannot Marshall the file struct")
	}
	//generate keys for file encryption and verification
	// fileKey := userlib.RandomBytes(16)
	fileEncrypt := userdata.FileEncryptKey
	// if ok6 != nil {
	// 	return errors.New("Cannot generate encryption key for the file")
	// }
	fileVerify := userdata.FileVerifyKey
	// if ok7 != nil {
	// 	return errors.New("Cannot generate verification key for the file")
	// }

	salt2 := userlib.RandomBytes(16)
	fileEncrypted := userlib.SymEnc(userdata.FileEncryptKey, salt2, hashedFile)
	fileHmac, ok9 := userlib.HMACEval(userdata.FileVerifyKey, fileEncrypted)
	if ok9 != nil {
		return errors.New("Cannot hmac the file struct")
	}

	var hmacFile HmacAndEnc
	hmacFile.Encrypted = fileEncrypted
	hmacFile.Hmaced = fileHmac

	marshalledData, ok5 := json.Marshal(hmacFile)
	if ok5 != nil {
		return errors.New("Cannot marshalled hmacFile")
	}

	randomUUID, ok10 := uuid.FromBytes(append(userlib.Hash([]byte(file.OriginalName))[:8], userlib.Hash([]byte(file.FileOwner))[:8]...))
	if ok10 != nil {
		return errors.New("Cannot generate UUID for the file struct")
	}
	//store the encrypted-then-mac user struct in the datastore.
	userlib.DatastoreSet(randomUUID, marshalledData)

	filemap[filename] = randomUUID

	marshalledUpdateMap, _ := json.Marshal(filemap)
	userlib.DatastoreSet(userdata.FilenametoUUID, marshalledUpdateMap)

	// fmt.Print(maps)
	// fmt.Print(userdata.FilenametoUUID)

	userdata.FilenametoKey = map[string]FileEncrypt{filename: {EncryptionKey: fileEncrypt[:16], VerificationKey: fileVerify[:16]}}

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	var file File
	var filehmac HmacAndEnc
	var filemap map[string]uuid.UUID
	marshalledMap, exists := userlib.DatastoreGet(userdata.FilenametoUUID)
	if exists != true {
		return nil, errors.New("cannot find filemap")
	}
	json.Unmarshal(marshalledMap, &filemap)

	fileID := filemap[filename]
	//get HMACed file struct from datastore by looking up the stored filename -> UUID in userstruct
	// filekey, _ := uuid.FromBytes(append(userlib.Hash([]byte(filename))[:8], userlib.Hash([]byte(userdata.Username))[:8]...))
	filemarshallhmac, exist := userlib.DatastoreGet(fileID)
	if exist != true {
		return nil, errors.New("Cannot find file with this name")
	}
	//unmarshall the Hmac and encrypt tuple from datastore and assign it to
	ok := json.Unmarshal(filemarshallhmac, &filehmac)
	if ok != nil {
		return nil, errors.New("Cannot unmarshall the HMACed file struct")
	}
	encryptedFile := filehmac.Encrypted
	hmacedFile := filehmac.Hmaced

	//recalculate hmac for file struct
	// fileverifyKey := userdata.FileVerifyKey
	// filedecryptKey := userdata.FileEncryptKey
	// var fileverifyKey []byte
	// marshalledKeyFile, _ := userlib.DatastoreGet(userdata.FileVerifyKey)
	// json.Unmarshal(marshalledKeyFile, &fileverifyKey)

	// var filedecryptKey []byte
	// marshalledEncFile, _ := userlib.DatastoreGet(userdata.FileEncryptKey)
	// json.Unmarshal(marshalledEncFile, &filedecryptKey)
	fileverifyKey := userdata.FileVerifyKey
	filedecryptKey := userdata.FileEncryptKey
	reHmac, ok1 := userlib.HMACEval(fileverifyKey, encryptedFile)
	if ok1 != nil {
		return nil, errors.New("Cannot recalculate the HMAC for file struct")
	}
	//if hmacs do not match, the file struct has been tampered with
	check := userlib.HMACEqual(reHmac, hmacedFile)
	if check != true {
		return nil, errors.New("The file struct has been tampered with")
	}
	//if the file struct is fine, decrypt it
	marshalledfile := userlib.SymDec(filedecryptKey, encryptedFile)
	check2 := json.Unmarshal(marshalledfile, &file)
	if check2 != nil {
		return nil, errors.New("Cannot unmarshall the file struct")
	}

	// fmt.Print(file.FileOwner)
	// fmt.Print(file.OriginalName)
	fmt.Print(file.ContentsPtrs)
	mapID, _ := uuid.FromBytes(append(userlib.Hash([]byte(file.FileOwner))[:8], userlib.Hash([]byte("sharemaps"))[:8]...))
	marshalledShareMap, _ := userlib.DatastoreGet(mapID)
	var sharemap map[string][]string
	json.Unmarshal(marshalledShareMap, &sharemap)

	file.FileSharedUser = sharemap

	valid := false
	for sender, receiver := range file.FileSharedUser {
		if sender == userdata.Username {
			valid = true
		}
		for i := 0; i < len(receiver); i++ {
			if receiver[i] == userdata.Username {
				valid = true
			}
		}
	}

	if valid == false {
		return nil, errors.New("not allowed to access")
	}

	//find the marshalled content hmac in datastore that we previously stored
	i := 0
	result := make([][]byte, file.NumberofAppend+1)
	var temp []byte
	for i < file.NumberofAppend+1 {
		marshalledcontenthmac, ok3 := userlib.DatastoreGet(file.ContentsPtrs[i])
		if ok3 != true {
			return nil, errors.New("Cannot find marshalled content hmac in datastore")
		}
		//check if the recalculated hmac still match the hmac stored in the struct
		var contenthmac HmacAndEnc
		check3 := json.Unmarshal(marshalledcontenthmac, &contenthmac)
		if check3 != nil {
			return nil, errors.New("Cannot unmarshall the content hmac")
		}
		encryptedcontent := contenthmac.Encrypted
		hmacedcontent := contenthmac.Hmaced

		//recalculate the hmac for the content
		recontenthmac, ok4 := userlib.HMACEval(file.ContentVerifyKeys[i], encryptedcontent)
		if ok4 != nil {
			return nil, errors.New("Cannot recalculate the hmac for the encrypted content")
		}
		//if hmacs do not match, the content has been tampered with
		check4 := userlib.HMACEqual(hmacedcontent, recontenthmac)
		if check4 != true {
			return nil, errors.New("the content has been tampered with")
		}
		//if the hmac is fine, we can then decrypt the content
		marshalledContent := userlib.SymDec(file.ContentEncryptKeys[i], encryptedcontent)
		check5 := json.Unmarshal(marshalledContent, &temp)
		if check5 != nil {
			return nil, errors.New("cannot unmarshalled the decrypted content")
		}
		result = append(result, temp)
		i = i + 1
	}
	for j := 0; j < len(result); j++ {
		content = append(content, result[j]...)
	}

	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	//check that the sender actually has this file
	var filemap map[string]uuid.UUID
	marshalledMap, exists := userlib.DatastoreGet(userdata.FilenametoUUID)
	if exists != true {
		return uuid.Nil, errors.New("cannot find filemap")
	}
	json.Unmarshal(marshalledMap, &filemap)

	_, isPresent := filemap[filename]
	if isPresent != true {
		return uuid.Nil, errors.New("sender does not have this file in his namespace")
	}
	//check if the recipient actually exist
	recipientUUID, _ := uuid.FromBytes(userlib.Hash([]byte(recipientUsername))[:16])
	_, exist := userlib.DatastoreGet(recipientUUID)
	if exist != true {
		return uuid.Nil, errors.New("cannot invite invalid user")
	}

	var originFile File
	var filehmac HmacAndEnc
	fileID := filemap[filename]

	filemarshallhmac, exist := userlib.DatastoreGet(fileID)
	if exist != true {
		return uuid.Nil, errors.New("Cannot find file with this name")
	}
	//unmarshall the Hmac and encrypt tuple from datastore and assign it to
	ok5 := json.Unmarshal(filemarshallhmac, &filehmac)
	if ok5 != nil {
		return uuid.Nil, errors.New("Cannot unmarshall the HMACed file struct")
	}
	encryptedFile := filehmac.Encrypted
	hmacedFile := filehmac.Hmaced

	fileverifyKey := userdata.FileVerifyKey
	filedecryptKey := userdata.FileEncryptKey
	reHmac, ok1 := userlib.HMACEval(fileverifyKey, encryptedFile)
	if ok1 != nil {
		return uuid.Nil, errors.New("Cannot recalculate the HMAC for file struct")
	}
	//if hmacs do not match, the file struct has been tampered with
	check := userlib.HMACEqual(reHmac, hmacedFile)
	if check != true {
		return uuid.Nil, errors.New("The file struct has been tampered with")
	}
	//if the file struct is fine, decrypt it
	marshalledfile := userlib.SymDec(filedecryptKey, encryptedFile)
	json.Unmarshal(marshalledfile, &originFile)

	mapID, _ := uuid.FromBytes(append(userlib.Hash([]byte(originFile.FileOwner))[:8], userlib.Hash([]byte("sharemaps"))[:8]...))
	marshalledShareMap, _ := userlib.DatastoreGet(mapID)
	var sharemap map[string][]string
	json.Unmarshal(marshalledShareMap, &sharemap)

	originFile.FileSharedUser = sharemap

	valid := false
	for sender, receiver := range originFile.FileSharedUser {
		if sender == userdata.Username {
			valid = true
		}
		for i := 0; i < len(receiver); i++ {
			if receiver[i] == userdata.Username {
				valid = true
			}
		}
	}

	if valid == false {
		return uuid.Nil, errors.New("not allowed to access")
	}

	//if the recipient actually exist, create invitation struct
	// var fileverifyKey []byte
	// marshalledKeyFile, _ := userlib.DatastoreGet(userdata.FileVerifyKey)
	// json.Unmarshal(marshalledKeyFile, &fileverifyKey)

	// var filedecryptKey []byte
	// marshalledEncFile, _ := userlib.DatastoreGet(userdata.FileEncryptKey)
	// json.Unmarshal(marshalledEncFile, &filedecryptKey)

	// fileverifyKey := userdata.FileVerifyKey
	// filedecryptKey := userdata.FileEncryptKey
	var invite Invitation
	fileIdtoShare := filemap[filename]
	invite.InviteFile = fileIdtoShare

	invite.FileEncrypt = filedecryptKey

	invite.FileVerify = fileverifyKey
	invite.Sender = userdata.Username
	invite.FileName = filename

	// fmt.Print(invite.sender)
	// marshalledSender, err := json.Marshal(userdata.Username)
	// if err != nil {
	// 	return uuid.Nil, errors.New("cannot marshall the invite")
	// }
	// // username := userdata.Username
	// senderID := uuid.New()
	// userlib.DatastoreSet(senderID, marshalledSender)

	//encrypt the invitation struct with recipient's public key
	var envelope Envelope
	recipientKey, ok := userlib.KeystoreGet(recipientUsername + "publicEnc")

	inviteKey := userlib.Hash([]byte(userdata.Username + recipientUsername))[:16]

	if ok != true {
		return uuid.Nil, errors.New("cannot find recipient's public key")
	}

	marshalledInvite, err := json.Marshal(invite)
	if err != nil {
		return uuid.Nil, errors.New("cannot marshall the invite")
	}
	encryptedInviteKey, err1 := userlib.PKEEnc(recipientKey, inviteKey)
	envelope.DecryptKey = encryptedInviteKey

	iv := userlib.RandomBytes(16)

	encryptedInvite := userlib.SymEnc(inviteKey, iv, marshalledInvite)
	envelope.EncryptInvite = encryptedInvite

	marshalledEnvelope, _ := json.Marshal(envelope)

	if err1 != nil {
		return uuid.Nil, errors.New("cannot encrypt the invite")
	}
	HmacedInvite, err2 := userlib.DSSign(userdata.DigitalSignatureKey, marshalledEnvelope)
	if err2 != nil {
		return uuid.Nil, errors.New("cannot sign the invite")
	}
	// fmt.Print("first marshalled invite")
	// fmt.Print(marshalledInvite)

	var HmacPair HmacAndEnc
	HmacPair.Encrypted = marshalledEnvelope
	HmacPair.Hmaced = HmacedInvite

	//marshall the hmacpair and store it to datastore
	marahlledHmacPair, _ := json.Marshal(HmacPair)
	inviteUUID, _ := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + recipientUsername))[:16])
	userlib.DatastoreSet(inviteUUID, marahlledHmacPair)

	return inviteUUID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	//check if called already have this filename in his namespace
	var filemap map[string]uuid.UUID
	marshalledMap, exists := userlib.DatastoreGet(userdata.FilenametoUUID)
	if exists != true {
		return errors.New("cannot find filemap")
	}
	json.Unmarshal(marshalledMap, &filemap)

	_, isPresent := filemap[filename]
	if isPresent == true {
		return errors.New("already have this filename in namespace")
	}

	//check if the invite is still valid
	_, isPresent = userlib.DatastoreGet(invitationPtr)
	if isPresent != true {
		return errors.New("the invitation is invalid")
	}

	marshalledHmacPair, ok := userlib.DatastoreGet(invitationPtr)
	if ok != true {
		return errors.New("cannot find corresponing invite struct in datastore")
	}

	var HmacPair HmacAndEnc
	ok1 := json.Unmarshal(marshalledHmacPair, &HmacPair)
	if ok1 != nil {
		return errors.New("cannot unmarshal the hmac pair")
	}

	marshaledEnvelope := HmacPair.Encrypted
	signedInvite := HmacPair.Hmaced

	//verify the integrity of the invite
	senderPublicKey, ok := userlib.KeystoreGet(senderUsername + "publicDig")
	if ok != true {
		return errors.New("cannot find the decrypt key")
	}
	ok2 := userlib.DSVerify(senderPublicKey, marshaledEnvelope, signedInvite)
	if ok2 != nil {
		return errors.New("cannot verify the integrity of the file")
	}

	// fmt.Print("first marshalled invite")
	// fmt.Print(marshalledInvite)
	//unmarshall the invite
	var envelope Envelope
	var invite Invitation
	err := json.Unmarshal(marshaledEnvelope, &envelope)

	if err != nil {
		return errors.New("cannot unmarshall the envelope")
	}

	encryptedInviteKey := envelope.DecryptKey

	decryptKey, _ := userlib.PKEDec(userdata.EncryptionKey, encryptedInviteKey)

	encryptedInvite := envelope.EncryptInvite

	marshalledinvite := userlib.SymDec(decryptKey, encryptedInvite)

	json.Unmarshal(marshalledinvite, &invite)

	// var sender string
	// senderMarshall, _ := userlib.DatastoreGet(invite.sender)
	// err = json.Unmarshal(senderMarshall, &sender)

	// if err != nil {
	// 	return errors.New("cannot unmarshall the name")
	// }

	//check if the sender is right
	//fmt.Print(invite.sender)
	//print("blablablablabla")
	//fmt.Print(senderUsername)
	if invite.Sender != senderUsername {
		return errors.New("the sender is incorrect")
	}

	//add the filename to namespace, add keys to corresponding maps
	// userdata.FilenametoUUID[filename] = invite.InviteFile

	// fmt.Print(invite.Sender)
	// fmt.Print("1")
	// fmt.Print(invite.FileEncrypt)
	// fmt.Print("2")
	// fmt.Print(invite.FileVerify)
	// fmt.Print("3")
	// fmt.Print(invite.InviteFile)
	// fmt.Print("4")

	var originFile File
	var filehmac HmacAndEnc
	filemap[filename] = invite.InviteFile
	userdata.FileEncryptKey = invite.FileEncrypt
	userdata.FileVerifyKey = invite.FileVerify
	marshalledUpdateMap, _ := json.Marshal(filemap)
	userlib.DatastoreSet(userdata.FilenametoUUID, marshalledUpdateMap)

	filemarshallhmac, exist := userlib.DatastoreGet(invite.InviteFile)
	if exist != true {
		return errors.New("Cannot find file with this name")
	}
	//unmarshall the Hmac and encrypt tuple from datastore and assign it to
	ok5 := json.Unmarshal(filemarshallhmac, &filehmac)
	if ok5 != nil {
		return errors.New("Cannot unmarshall the HMACed file struct")
	}
	encryptedFile := filehmac.Encrypted
	hmacedFile := filehmac.Hmaced

	fileverifyKey := userdata.FileVerifyKey
	filedecryptKey := userdata.FileEncryptKey
	reHmac, ok1 := userlib.HMACEval(fileverifyKey, encryptedFile)
	if ok1 != nil {
		return errors.New("Cannot recalculate the HMAC for file struct")
	}
	//if hmacs do not match, the file struct has been tampered with
	check := userlib.HMACEqual(reHmac, hmacedFile)
	if check != true {
		return errors.New("The file struct has been tampered with")
	}
	//if the file struct is fine, decrypt it
	marshalledfile := userlib.SymDec(filedecryptKey, encryptedFile)
	json.Unmarshal(marshalledfile, &originFile)

	fmt.Print(originFile.FileSharedUser)
	originFile.FileSharedUser[senderUsername] = append(originFile.FileSharedUser[senderUsername], userdata.Username)
	fmt.Print(originFile.FileSharedUser)

	var shareMap map[string][]string
	shareMap = originFile.FileSharedUser

	marshalledShareMap, _ := json.Marshal(shareMap)
	shareID, _ := uuid.FromBytes(append(userlib.Hash([]byte(originFile.FileOwner))[:8], userlib.Hash([]byte("sharemaps"))[:8]...))
	userlib.DatastoreSet(shareID, marshalledShareMap)

	var file File
	file.OriginalName = originFile.OriginalName
	file.FileOwner = originFile.FileOwner

	// fmt.Print(file.OriginalName)
	// fmt.Print(file.FileOwner)

	marshalledFile, _ := json.Marshal(file)

	randomUUID, _ := uuid.FromBytes(append(userlib.Hash([]byte(filename))[:8], userlib.Hash([]byte(userdata.Username))[:8]...))

	userlib.DatastoreSet(randomUUID, marshalledFile)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	inviteUUID, _ := uuid.FromBytes(userlib.Hash([]byte(userdata.Username + recipientUsername))[:16])
	userlib.DatastoreDelete(inviteUUID)

	var filemap map[string]uuid.UUID
	marshalledMap, exists := userlib.DatastoreGet(userdata.FilenametoUUID)
	if exists != true {
		return errors.New("cannot find filemap")
	}
	json.Unmarshal(marshalledMap, &filemap)

	_, isPresent := filemap[filename]
	if isPresent == false {
		return errors.New("don't have this filename in namespace")
	}

	var originFile File
	var filehmac HmacAndEnc
	fileID := filemap[filename]

	filemarshallhmac, exist := userlib.DatastoreGet(fileID)
	if exist != true {
		return errors.New("Cannot find file with this name")
	}
	//unmarshall the Hmac and encrypt tuple from datastore and assign it to
	ok5 := json.Unmarshal(filemarshallhmac, &filehmac)
	if ok5 != nil {
		return errors.New("Cannot unmarshall the HMACed file struct")
	}
	encryptedFile := filehmac.Encrypted
	hmacedFile := filehmac.Hmaced

	fileverifyKey := userdata.FileVerifyKey
	filedecryptKey := userdata.FileEncryptKey
	reHmac, ok1 := userlib.HMACEval(fileverifyKey, encryptedFile)
	if ok1 != nil {
		return errors.New("Cannot recalculate the HMAC for file struct")
	}
	//if hmacs do not match, the file struct has been tampered with
	check := userlib.HMACEqual(reHmac, hmacedFile)
	if check != true {
		return errors.New("The file struct has been tampered with")
	}
	//if the file struct is fine, decrypt it
	marshalledfile := userlib.SymDec(filedecryptKey, encryptedFile)
	json.Unmarshal(marshalledfile, &originFile)

	delete(originFile.FileSharedUser, recipientUsername)
	for _, receiver := range originFile.FileSharedUser {
		for i := 0; i < len(receiver); i++ {
			if receiver[i] == recipientUsername {
				receiver[i] = ""
			}
		}
	}

	var shareMap map[string][]string
	shareMap = originFile.FileSharedUser

	marshalledShareMap, _ := json.Marshal(shareMap)
	shareID, _ := uuid.FromBytes(append(userlib.Hash([]byte(originFile.FileOwner))[:8], userlib.Hash([]byte("sharemaps"))[:8]...))
	userlib.DatastoreSet(shareID, marshalledShareMap)

	return nil
}
