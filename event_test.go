package whatsmeow

import (
	"bytes"
	"context"
	"testing"

	"google.golang.org/protobuf/proto"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
)

type eventSecretStore struct {
	chat   types.JID
	sender types.JID
	id     types.MessageID
	secret []byte
}

func (s *eventSecretStore) PutMessageSecrets(_ context.Context, inserts []store.MessageSecretInsert) error {
	for _, insert := range inserts {
		if insert.ID == s.id {
			s.secret = bytes.Clone(insert.Secret)
			s.chat = insert.Chat
			s.sender = insert.Sender
		}
	}
	return nil
}

func (s *eventSecretStore) PutMessageSecret(_ context.Context, chat, sender types.JID, id types.MessageID, secret []byte) error {
	s.chat, s.sender, s.id, s.secret = chat, sender, id, bytes.Clone(secret)
	return nil
}

func (s *eventSecretStore) GetMessageSecret(_ context.Context, chat, _ types.JID, id types.MessageID) ([]byte, types.JID, error) {
	if chat != s.chat || id != s.id {
		return nil, types.EmptyJID, nil
	}
	return bytes.Clone(s.secret), s.sender, nil
}

func newEventTestClient(t *testing.T, creator types.JID, fromMe bool) (*Client, *types.MessageInfo) {
	t.Helper()
	ownPN := types.NewJID("491111111111", types.DefaultUserServer)
	ownLID := types.NewJID("100000000001", types.HiddenUserServer)
	group := types.NewJID("120000000000000001", types.GroupServer)
	eventID := types.MessageID("EVENT-ORIGINAL-ID")
	secretStore := &eventSecretStore{
		chat:   group,
		sender: creator,
		id:     eventID,
		secret: bytes.Repeat([]byte{0x42}, 32),
	}
	device := &store.Device{ID: &ownPN, LID: ownLID, MsgSecrets: secretStore}
	return NewClient(device, nil), &types.MessageInfo{
		MessageSource: types.MessageSource{
			Chat:     group,
			Sender:   creator,
			IsFromMe: fromMe,
			IsGroup:  true,
		},
		ID: eventID,
	}
}

func TestBuildEventCreationAddsSecret(t *testing.T) {
	cli := &Client{}
	input := &waE2E.EventMessage{Name: proto.String("Dinner")}
	msg := cli.BuildEventCreation(input)

	if msg.GetEventMessage().GetName() != "Dinner" {
		t.Fatalf("unexpected event name: %q", msg.GetEventMessage().GetName())
	}
	if len(msg.GetMessageContextInfo().GetMessageSecret()) != 32 {
		t.Fatalf("message secret length = %d, want 32", len(msg.GetMessageContextInfo().GetMessageSecret()))
	}
	if input.IsCanceled != nil {
		t.Fatal("BuildEventCreation mutated caller input")
	}
}

func TestEventResponseEncryptionRoundTrip(t *testing.T) {
	creator := types.NewJID("100000000099", types.HiddenUserServer)
	cli, eventInfo := newEventTestClient(t, creator, false)

	built, err := cli.BuildEventResponse(
		context.Background(),
		eventInfo,
		waE2E.EventResponseMessage_GOING,
		2,
	)
	if err != nil {
		t.Fatalf("BuildEventResponse failed: %v", err)
	}
	received := &events.Message{
		Info: types.MessageInfo{MessageSource: types.MessageSource{
			Chat:    eventInfo.Chat,
			Sender:  cli.getOwnLID(),
			IsGroup: true,
		}},
		Message: built,
	}
	decrypted, err := cli.DecryptEventResponse(context.Background(), received)
	if err != nil {
		t.Fatalf("DecryptEventResponse failed: %v", err)
	}
	if decrypted.GetResponse() != waE2E.EventResponseMessage_GOING || decrypted.GetExtraGuestCount() != 2 {
		t.Fatalf("unexpected decrypted response: %s / %d", decrypted.GetResponse(), decrypted.GetExtraGuestCount())
	}
}

func TestEventEditEncryptionRoundTrip(t *testing.T) {
	creator := types.NewJID("100000000001", types.HiddenUserServer)
	cli, eventInfo := newEventTestClient(t, creator, true)
	updated := &waE2E.EventMessage{
		Name:       proto.String("Updated dinner"),
		IsCanceled: proto.Bool(true),
	}

	built, err := cli.BuildEventEdit(context.Background(), eventInfo, updated)
	if err != nil {
		t.Fatalf("BuildEventEdit failed: %v", err)
	}
	received := &events.Message{
		Info: types.MessageInfo{MessageSource: types.MessageSource{
			Chat:      eventInfo.Chat,
			Sender:    cli.getOwnLID(),
			SenderAlt: cli.getOwnID(),
			IsFromMe:  true,
			IsGroup:   true,
		}},
		Message: built,
	}
	received.Info.ID = "EVENT-EDIT-ID"
	encrypted := received.Message.GetSecretEncryptedMessage()
	plaintext, err := cli.decryptMsgSecret(
		context.Background(),
		received,
		EncSecretEventEdit,
		encrypted,
		encrypted.GetTargetMessageKey(),
	)
	if err != nil {
		t.Fatalf("decrypt raw event edit failed: %v", err)
	}
	var wireMessage waE2E.Message
	if err = proto.Unmarshal(plaintext, &wireMessage); err != nil {
		t.Fatalf("decode raw event edit failed: %v", err)
	}
	wireEvent := wireMessage.GetEventMessage()
	if wireEvent == nil || wireEvent.GetName() != "Updated dinner" || !wireEvent.GetIsCanceled() {
		t.Fatalf("event edit wire payload is not Message{EventMessage}: %v", &wireMessage)
	}
	if encrypted.GetTargetMessageKey().GetParticipant() != "" {
		t.Fatalf("from-me event target contains participant: %q", encrypted.GetTargetMessageKey().GetParticipant())
	}
	decrypted, err := cli.DecryptSecretEncryptedMessage(context.Background(), received)
	if err != nil {
		t.Fatalf("DecryptSecretEncryptedMessage failed: %v", err)
	}
	if decrypted.GetEventMessage().GetName() != "Updated dinner" || !decrypted.GetEventMessage().GetIsCanceled() {
		t.Fatalf("unexpected decrypted event edit: %v", decrypted.GetEventMessage())
	}
}

func TestDecryptEventEditAcceptsLegacyDirectPayload(t *testing.T) {
	creator := types.NewJID("100000000001", types.HiddenUserServer)
	cli, eventInfo := newEventTestClient(t, creator, true)
	direct := &waE2E.EventMessage{Name: proto.String("Legacy direct event")}
	plaintext, err := proto.Marshal(direct)
	if err != nil {
		t.Fatalf("marshal direct event: %v", err)
	}
	ciphertext, iv, err := cli.encryptMsgSecret(
		context.Background(),
		cli.getOwnID(),
		eventInfo.Chat,
		eventInfo.Sender,
		eventInfo.ID,
		EncSecretEventEdit,
		plaintext,
	)
	if err != nil {
		t.Fatalf("encrypt direct event: %v", err)
	}
	received := &events.Message{
		Info: types.MessageInfo{MessageSource: types.MessageSource{
			Chat: eventInfo.Chat, Sender: cli.getOwnID(), IsFromMe: true, IsGroup: true,
		}},
		Message: &waE2E.Message{SecretEncryptedMessage: &waE2E.SecretEncryptedMessage{
			TargetMessageKey: getKeyFromInfo(eventInfo),
			EncPayload:       ciphertext,
			EncIV:            iv,
			SecretEncType:    waE2E.SecretEncryptedMessage_EVENT_EDIT.Enum(),
		}},
	}
	decrypted, err := cli.DecryptSecretEncryptedMessage(context.Background(), received)
	if err != nil {
		t.Fatalf("decrypt direct event: %v", err)
	}
	if decrypted.GetEventMessage().GetName() != "Legacy direct event" {
		t.Fatalf("unexpected legacy event: %v", decrypted.GetEventMessage())
	}
}

func TestEventEditUsesPhoneIdentityForHKDF(t *testing.T) {
	creator := types.NewJID("100000000001", types.HiddenUserServer)
	cli, eventInfo := newEventTestClient(t, creator, true)
	built, err := cli.BuildEventEdit(
		context.Background(),
		eventInfo,
		&waE2E.EventMessage{Name: proto.String("Phone identity edit")},
	)
	if err != nil {
		t.Fatalf("BuildEventEdit failed: %v", err)
	}
	received := &events.Message{
		Info: types.MessageInfo{MessageSource: types.MessageSource{
			Chat: eventInfo.Chat, Sender: cli.getOwnID(), IsFromMe: true, IsGroup: true,
		}},
		Message: built,
	}
	decrypted, err := cli.DecryptSecretEncryptedMessage(context.Background(), received)
	if err != nil {
		t.Fatalf("phone identity could not decrypt event edit: %v", err)
	}
	if decrypted.GetEventMessage().GetName() != "Phone identity edit" {
		t.Fatalf("unexpected event edit: %v", decrypted.GetEventMessage())
	}
}

func TestEventWireClassification(t *testing.T) {
	tests := []struct {
		name      string
		message   *waE2E.Message
		eventType string
		edit      types.EditAttribute
	}{
		{"creation", &waE2E.Message{EventMessage: &waE2E.EventMessage{}}, "creation", types.EditAttributeEmpty},
		{"response", &waE2E.Message{EncEventResponseMessage: &waE2E.EncEventResponseMessage{}}, "response", types.EditAttributeEmpty},
		{"edit", &waE2E.Message{SecretEncryptedMessage: &waE2E.SecretEncryptedMessage{
			SecretEncType: waE2E.SecretEncryptedMessage_EVENT_EDIT.Enum(),
		}}, "edit", types.EditAttributeMessageEdit},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := getTypeFromMessage(tc.message); got != "event" {
				t.Fatalf("message type = %q, want event", got)
			}
			if got := getEditAttribute(tc.message); got != tc.edit {
				t.Fatalf("edit attribute = %q, want %q", got, tc.edit)
			}
			content := (&Client{}).getMessageContent(
				waBinary.Node{Tag: "enc"},
				tc.message,
				waBinary.Attrs{"type": "event"},
				false,
				nodeExtraParams{},
			)
			if len(content) != 2 {
				t.Fatalf("content nodes = %d, want 2", len(content))
			}
			if got := content[1].Attrs["event_type"]; got != tc.eventType {
				t.Fatalf("event_type = %v, want %q", got, tc.eventType)
			}
		})
	}
}
