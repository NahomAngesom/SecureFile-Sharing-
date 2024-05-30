package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	"strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	dorisFile := "dorisFile.txt"
	eveFile := "eveFile.txt"
	frankFile := "frankFile.txt"
	graceFile := "graceFile.txt"
	horaceFile := "horaceFile.txt"
	iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		Specify("InitUser: The client SHOULD assume that each user has a unique username.", func() {
			userlib.DebugMsg("create alice")
			_, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create alice again")
			_, err2 := client.InitUser("alice", defaultPassword)
			Expect(err2).ToNot(BeNil())
		})

		Specify("InitUser: Usernames are case-sensitive: Bob and bob are different users.", func() {
			userlib.DebugMsg("create Alice")
			_, err := client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create alice again")
			_, err2 := client.InitUser("alice", defaultPassword)
			Expect(err2).To(BeNil())
		})

		Specify("InitUser: The client SHOULD support usernames of any length greater than zero.", func() {
			userlib.DebugMsg("create Alice")
			_, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create nobody")
			_, err2 := client.InitUser("", defaultPassword)
			Expect(err2).ToNot(BeNil())
		})

		Specify("InitUser: The client MUST NOT assume each user has a unique password. Like the real world, users may happen to choose the same password.", func() {
			userlib.DebugMsg("create Alice")
			_, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create alice")
			_, err2 := client.InitUser("Alice", defaultPassword)
			Expect(err2).To(BeNil())
		})

		Specify("InitUser: The client SHOULD support passwords length greater than or equal to zero.", func() {
			userlib.DebugMsg("create Alice")
			_, err := client.InitUser("alice", "")
			Expect(err).To(BeNil())
		})

		Specify("GetUser: There is no initialized user for the given username.", func() {
			userlib.DebugMsg("create Alice")
			_, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("get bob")
			_, err2 := client.GetUser("bob", defaultPassword)
			Expect(err2).ToNot(BeNil())
		})

		Specify("GetUser: The user credentials are invalid.", func() {
			userlib.DebugMsg("create Alice")
			_, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("get alice with wrong password")
			_, err2 := client.GetUser("alice", emptyString)
			Expect(err2).ToNot(BeNil())
		})

		Specify("StoreFile: Filenames MAY be any length, including zero (empty string).", func() {
			userlib.DebugMsg("create alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create file for alice with no name")
			err = alice.StoreFile(emptyString, []byte(contentOne))
			Expect(err).To(BeNil())
		})

		Specify("LoadFile: The given filename does not exist in the personal file namespace of the caller.", func() {
			userlib.DebugMsg("create Alice")
			_, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create alicefile but try to load bobfile")
			alice.StoreFile(aliceFile, []byte(contentOne))
			_, err2 := alice.LoadFile(bobFile)
			Expect(err2).ToNot(BeNil())
		})

		Specify("AppendToFile: The given filename does not exist in the personal file namespace of the caller.", func() {
			userlib.DebugMsg("create Alice")
			_, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create alicefile but try to append to bobfile")
			alice.StoreFile(aliceFile, []byte(contentOne))
			err2 := alice.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err2).ToNot(BeNil())
		})

		//define the function to measurebandwidth
		measureBandwidth := func(probe func()) (bandwidth int) {
			before := userlib.DatastoreGetBandwidth()
			probe()
			after := userlib.DatastoreGetBandwidth()
			return after - before
		}

		Specify("AppendToFile: efficiency", func() {
			userlib.DebugMsg("create alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			superlargeFile := strings.Repeat(contentOne, 100000)
			err = alice.StoreFile(aliceFile, []byte(superlargeFile))
			Expect(err).To(BeNil())

			userlib.DebugMsg("bandwidth used to load the file")
			bandwidthWithoutAppend := measureBandwidth(func() {
				_, err := alice.LoadFile(aliceFile)
				Expect(err).To(BeNil())
			})

			userlib.DebugMsg("bandwidth used to load the appended file")
			bandwidthWithAppend := measureBandwidth(func() {
				err = alice.AppendToFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())
			})

			userlib.DebugMsg("append bandwidth should be within 100000 times of the contentOne")
			Expect(bandwidthWithoutAppend > bandwidthWithAppend*100000)
		})

		Specify("CreateInvitation: The given filename does not exist in the personal file namespace of the caller.", func() {
			userlib.DebugMsg("create Alice")
			_, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create bob")
			_, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create alicefile but try to share bobfile")
			alice.StoreFile(aliceFile, []byte(contentOne))
			_, err2 := alice.CreateInvitation(bobFile, "bob")
			Expect(err2).ToNot(BeNil())
		})

		Specify("Accpetinvitation: the user cannot accept invitation if it is revoked", func() {
			userlib.DebugMsg("create alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create alicefile for alice")
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("alice invite bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice revokes bob")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob cannot accept invite")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("AcceptInvitation: The caller already has a file with the given filename in their personal file namespace.", func() {
			userlib.DebugMsg("create alice")
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create alicefile for alice")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("create alicefile for bob")
			err = bob.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Check Alice can access alicefile")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Check bob can access alicefile")
			data, err = bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))

			userlib.DebugMsg("Create invitation for bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("check bob cannot accept the invitation")
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("AcceptInvitation: The caller already has a file with the given filename in their personal file namespace.", func() {
			userlib.DebugMsg("create alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create alicefile for alice")
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("create bobfile for bob")
			bob.StoreFile(bobFile, []byte(contentOne))

			userlib.DebugMsg("alice invites bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob cannot name the shared file as bobfile")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("LoadFile: cannot load file that do not exist", func() {
			userlib.DebugMsg("create alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Check alice cannot load file")
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("LoadFile: try to load file that do not have access", func() {
			userlib.DebugMsg("create alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create alicefile for alice")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Check bob cannot load alicefile")
			_, err = bob.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

		})

		Specify("CreateInvitation: cannot share a file that sender has no access to", func() {
			userlib.DebugMsg("create alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice invites Bob")
			_, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Invite non-exist user", func() {
			userlib.DebugMsg("create alice")
			alice, err = client.InitUser("alice", defaultPassword)

			userlib.DebugMsg("create alicefile for alice")
			err = alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("alice invite bob, who is not created")
			_, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("LoadFile: shared user can load the same file", func() {
			userlib.DebugMsg("create alcie")
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create charles")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create alicefile for alice")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("share alicefile with bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob accept invite")
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Check bob can access alicefile")
			data, err := bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Check charles cannot access alicefile")
			_, err = charles.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

		})

		Specify("Delete User Struct", func() {
			userlib.DebugMsg("create bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("recalculate all information about bob")
			username := "bob"
			usernameBytes := []byte(username)
			hashed := userlib.Hash(usernameBytes)[:16]
			userUUID, err := uuid.FromBytes(hashed)
			Expect(err).To(BeNil())

			userlib.DebugMsg("delete bob from datastore")
			userlib.DatastoreDelete(userUUID)

			userlib.DebugMsg("bob should no longer be a valid user")
			_, err = client.GetUser("bob", defaultPassword)
			Expect(err).ToNot(BeNil())

		})

		Specify("StoreFile: shared users can store to the shared file", func() {

			userlib.DebugMsg("Create Alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates alicefile")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice invites Bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepts invite and rename it bobfile")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob stores bobfile")
			err = bob.StoreFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("check Alice has same file as bob")
			content, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentTwo)))

			userlib.DebugMsg("chech bob has the same file as alice")
			content, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentTwo)))
		})

		Specify("Loaded file should be reflected in multiple devices of the same users", func() {
			userlib.DebugMsg("create alice phone")
			alicePhone, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create alice laptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			err = alicePhone.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			content, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentOne + contentTwo)))

		})

		Specify("AcceptInvitation: you cannot accept invitation that's not direct sent from another user", func() {
			userlib.DebugMsg("create alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create alicefile for alice")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			invite, _ := uuid.FromBytes(userlib.RandomBytes(16))
			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).ToNot(BeNil())

		})

		Specify("RevokeAccess: cannot revoke a file that sender does not own, or the shared person do not have", func() {
			userlib.DebugMsg("create alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice has alice but bob dont")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob has bobfile but Alice dont")
			err = bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revokes alicefile")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice revokes bobfile")
			err = alice.RevokeAccess(bobFile, "bob")
			Expect(err).ToNot(BeNil())

		})

		Specify("RevokeAccess: revokes user cannot loadfile, change file, appendtofile, or create invitations", func() {
			userlib.DebugMsg("create alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create charles")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create doris")
			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create alicefile for alice")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice invites bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice invites charles")
			invite2, err := alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepts invite")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("charles accepts invite")
			err = charles.AcceptInvitation("alice", invite2, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revokes charles")
			err = alice.RevokeAccess(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("charles loadfile")
			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("charles storefile")
			err = charles.StoreFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("charles appendFile")
			err = charles.AppendToFile(charlesFile, []byte(contentThree))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("charles invite doris")
			invite3, err := charles.CreateInvitation(charlesFile, "doris")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("doris cannot accept invitation")
			err = doris.AcceptInvitation("charles", invite3, dorisFile)
			Expect(err).ToNot(BeNil())

		})

		Specify("RevokeAccess: make sure revoking does not affect other files", func() {
			userlib.DebugMsg("create alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create alicefile for alice")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice invite bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepts invite")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob can load alicefile")
			content, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("create more files for bob")
			err = bob.StoreFile(charlesFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("create dorisfile for bob")
			err = bob.StoreFile(dorisFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice revokes bob")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob can not load bobfile anymore")
			content, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("bob can still load charlesfile")
			content, err = bob.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentTwo)))

			userlib.DebugMsg("Bob can still load dorisfile")
			content, err = bob.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte(contentThree)))
		})

		Specify("RevokeAccess: revoking one user does not affect other users", func() {
			userlib.DebugMsg("create alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create charles")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create alicefile for alice")
			err := alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice invites bob")
			fooInvPtr, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob accepts invite")
			err = bob.AcceptInvitation("alice", fooInvPtr, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice intive charles")
			invite, err := alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice revokes bob")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("charles accepts alice's invite")
			err = charles.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("charles can still load alicefile")
			Content, err := charles.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(Content).To(Equal([]byte(contentOne)))
		})

		Specify("RevokeAccess: check revoking tree", func() {
			userlib.DebugMsg("create alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create charles")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create doris")
			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create alicefile for alice")
			alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice share with bob")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob accept invite")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob share with charles")
			invite2, err := bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("bob share with doris")
			invite3, err := bob.CreateInvitation(bobFile, "doris")
			Expect(err).To(BeNil())

			userlib.DebugMsg("charles accept invite")
			err = charles.AcceptInvitation("bob", invite2, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("doris accept invite")
			err = doris.AcceptInvitation("bob", invite3, dorisFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice revokes bob")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("charles and doris cannot load the file")
			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())
			_, err = doris.LoadFile(dorisFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("However, the number of keys in Keystore per user MUST be a small constant;", func() {
			userlib.DebugMsg("create alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			original := len(userlib.KeystoreGetMap())

			userlib.DebugMsg("create alicefile for alice")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("create bobfile for alice")
			err = alice.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("create multiple files")
			err = alice.StoreFile(charlesFile, []byte(contentOne))
			Expect(err).To(BeNil())
			err = alice.StoreFile(dorisFile, []byte(contentOne))
			Expect(err).To(BeNil())
			err = alice.StoreFile(eveFile, []byte(contentOne))
			Expect(err).To(BeNil())
			err = alice.StoreFile(frankFile, []byte(contentOne))
			Expect(err).To(BeNil())
			err = alice.StoreFile(graceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			err = alice.StoreFile(horaceFile, []byte(contentOne))
			Expect(err).To(BeNil())
			err = alice.StoreFile(iraFile, []byte(contentOne))
			Expect(err).To(BeNil())

			after := len(userlib.KeystoreGetMap())
			Expect(after).To(Equal(original))
		})

		Specify("Check error when the user struct does not belong to the username and password", func() {
			userlib.DebugMsg("create alice")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("create bob")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("get alice's user struct UUID")
			aliceUsernameBytes := []byte("alice")
			aliceUsernameBytesHashed := userlib.Hash(aliceUsernameBytes)[:16]
			aliceUUID, err := uuid.FromBytes(aliceUsernameBytesHashed)
			Expect(err).To(BeNil())

			userlib.DebugMsg("get bob's user struct UUID")
			bobUsernameBytes := []byte("bob")
			bobUsernameBytesHashed := userlib.Hash(bobUsernameBytes)[:16]
			bobUUID, err := uuid.FromBytes(bobUsernameBytesHashed)
			Expect(err).To(BeNil())

			userlib.DebugMsg("get alice's user struct and bob's user struct")
			dataStoreMap := userlib.DatastoreGetMap()
			alicetemp := dataStoreMap[aliceUUID]
			userlib.DebugMsg("inter changed alice's and bob's user struct")
			dataStoreMap[aliceUUID] = dataStoreMap[bobUUID]
			dataStoreMap[bobUUID] = alicetemp

			userlib.DebugMsg("should return error when get alice")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("should return error when get bob")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).ToNot(BeNil())

		})

	})
})
